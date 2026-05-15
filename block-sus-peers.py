#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import time
from datetime import datetime

try:
    import qbittorrentapi
except ImportError:
    sys.exit("CRITICAL: 'qbittorrentapi' module is not installed. Please run: pip install qbittorrent-api")

# Default list of unwanted or spam clients (Xunlei/Thunder/Fake clients)
DEFAULT_BLOCK_LIST = ['xunlei', 'xl00', 'thunder', 'xfwl', 'unknown', 'top-bt', 'torrent+']

def parse_arguments():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="qBittorrent Peer Guard: Automated utility to filter and block unwanted peers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Connection parameters
    parser.add_argument('--host', type=str, default='127.0.0.1:8080', help='qBittorrent WebUI address (host:port)')
    parser.add_argument('--user', type=str, default=os.getenv('QBT_USER', 'admin'), help='Username (or QBT_USER env var)')
    parser.add_argument('--pass', dest='password', type=str, default=os.getenv('QBT_PASS', ''), help='Password (or QBT_PASS env var)')
    
    # Operation parameters
    parser.add_argument('--interval', type=float, default=2.0, help='Scan interval in seconds')
    parser.add_argument('--threshold', type=int, default=52428800, help='Upload threshold in bytes for zero-progress peers (default 50 MB)')
    
    # Logging & Mode Flags
    parser.add_argument('--log-file', type=str, default=None, help='Path to the structured log file (disabled if omitted)')
    parser.add_argument('--silent', action='store_true', help='Disable standard console output (stdout)')
    parser.add_argument('--dry-run', action='store_true', help='Simulation mode: identify peers without actual blocking')
    
    return parser.parse_args()


def setup_logging(silent):
    """Configures internal runtime logging for diagnostics (stdout only)."""
    handlers = []
    if not silent:
        handlers.append(logging.StreamHandler(sys.stdout))
    else:
        handlers.append(logging.NullHandler())
        
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )
    return logging.getLogger("PeerGuard")


def initialize_tabular_log(file_path):
    """Creates the structural file header if the target log file does not exist."""
    if not file_path or os.path.exists(file_path):
        return
        
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            header = f"{'DATE TIME':<16} | {'IP':<40} | {'FLAGS':<12} | {'PROG':<6} | {'UPLOADED':<10} | {'DOWNLOADED':<10} | {'REASON':<30} | CLIENT\n"
            divider = "-" * len(header) + "\n"
            f.write(header)
            f.write(divider)
    except Exception as e:
        print(f"CRITICAL: Failed to initialize log file at {file_path}: {e}", file=sys.stderr)


def log_ban_to_tabular_file(file_path, info, reason):
    """Appends a single structured entry to the flat-file database layout."""
    if not file_path:
        return
        
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        ip = info.get('ip', '0.0.0.0')
        flags = info.get('flags', '').strip()
        
        raw_progress = info.get('progress', 0.0)
        progress_str = f"{raw_progress:.1%}" if raw_progress <= 1.0 else f"{raw_progress}%"
        
        uploaded = str(info.get('uploaded', 0))
        downloaded = str(info.get('downloaded', 0))
        client = info.get('client', '').strip()
        
        line = f"{timestamp:<16} | {ip:<40} | {flags:<12} | {progress_str:<6} | {uploaded:<10} | {downloaded:<10} | {reason:<30} | {client}\n"
        
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception as e:
        # Avoid crashing the script loop if file system IO drops temporarily
        pass


def check_peer_rules(info, threshold):
    """
    Analyzes peer parameters against filtering rules.
    Returns: tuple(bool: should_ban, str: reason)
    """
    if not isinstance(info, dict):
        return False, ""

    client_name = info.get('client', '').strip().lower()
    flags = str(info.get('flags', ''))
    progress = float(info.get('progress', 0.0))
    uploaded = int(info.get('uploaded', 0))
    
    # 1. Empty or unidentified client
    if not client_name:
        return True, "EMPTY_CLIENT_NAME"
        
    # 2. Match against block list (parasitic clients)
    if any(bot_tag in client_name for bot_tag in DEFAULT_BLOCK_LIST):
        return True, "BLACKLISTED_CLIENT"
        
    # 3. Anomalous upload with zero progress (Leecher bots)
    if uploaded > threshold and progress == 0.0:
        return True, "EXCESSIVE_UPLOAD_ZERO_PROGRESS"
        
    # 4. Inactive PEX/garbage connections (accumulated dead weight)
    is_dead_pex = ('X' in flags and progress == 0.0 and uploaded == 0 and 'S' not in flags)
    is_dead_weight = (progress == 0.0 and uploaded == 0 and 'S' not in flags and ('X' in flags or 'h' in flags))
    
    if is_dead_pex or is_dead_weight:
        return True, "INACTIVE_PEX_CONN"
        
    return False, ""


def process_torrent_peers(qbt, torrent_hash, threshold, dry_run, log_file, logger):
    """Fetches and filters peers for a specific torrent execution loop."""
    banned_in_torrent = 0
    to_ban_list = []
    try:
        peer_data = qbt.sync_torrent_peers(torrent_hash)
        if not peer_data or 'peers' not in peer_data:
            return 0
            
        peers = peer_data['peers']
    except Exception as e:
        logger.debug(f"Failed to fetch peers for torrent {torrent_hash}: {e}")
        return 0

    for ip_port, info in peers.items():
        should_ban, reason = check_peer_rules(info, threshold)
        
        if should_ban:
            pure_ip = info.get('ip', ip_port.rsplit(':', 1)[0] if ':' in ip_port else ip_port)
            client = info.get('client', 'Unknown')
            flags = info.get('flags', 'N/A')
            
            log_msg = f"[{reason}] IP: {pure_ip} | Client: {client} | Flags: {flags}"
            
            if dry_run:
                logger.info(f"[DRY-RUN] [MATCH] {log_msg}")
            else:
                logger.info(f"[BAN] {log_msg}")
                log_ban_to_tabular_file(log_file, info, reason)
                try:
                    to_ban_list.append((ip_port, info, reason))
                    banned_in_torrent += 1
                except Exception as e:
                    logger.error(f"Failed to ban peer {ip_port}: {e}")
                    
    return to_ban_list


def verify_connection(qbt, logger):
    """Verifies authentication and API responsiveness."""
    try:
        qbt.auth_log_in()
        app_version = qbt.app_version()
        logger.info(f"Successfully connected to qBittorrent v{app_version}")
        return True
    except qbittorrentapi.LoginFailed:
        logger.critical("Authentication failed. Check your username and password.")
        return False
    except qbittorrentapi.APIConnectionError as e:
        logger.critical(f"Connection error. Check host address and port: {e}")
        return False
    except Exception as e:
        logger.critical(f"Unexpected connection error: {e}")
        return False


def main():
    args = parse_arguments()
    logger = setup_logging(args.silent)
    
    logger.info("Initializing qBittorrent Peer Guard...")
    if args.dry_run:
        logger.info("WARNING: Running in simulation mode (--dry-run). No bans will be applied.")
        
    if args.log_file:
        initialize_tabular_log(args.log_file)
        logger.info(f"Structured tabular logging enabled at: {args.log_file}")
    else:
        logger.info("NOTE: Tabular file logging is disabled. Runtime bans won't be written to disk.")

    qbt = qbittorrentapi.Client(host=args.host, username=args.user, password=args.password)
    
    if not verify_connection(qbt, logger):
        sys.exit(1)

    consecutive_errors = 0
    
    while True:
        try:
            active_torrents = qbt.torrents_info(status_filter='active')
            all_to_ban = []

            if active_torrents:
                for torrent in active_torrents:
                    all_to_ban += process_torrent_peers(
                        qbt, torrent.hash, args.threshold, args.dry_run, args.log_file, logger
                    )
            
            if all_to_ban:
                if not args.dry_run:
                    ips_string = '|'.join([peer[0] for peer in all_to_ban])
                    try:
                        qbt.transfer_ban_peers(peers=ips_string)
                        
                        for ip_port, info, reason in all_to_ban:
                            pure_ip = info.get('ip', ip_port.rsplit(':', 1)[0] if ':' in ip_port else ip_port)
                            client = info.get('client', 'Unknown')
                            flags = info.get('flags', 'N/A')
                            logger.info(f"[BAN] [{reason}] IP: {pure_ip} | Client: {client} | Flags: {flags}")
                        
                        logger.info(f"Cleanup cycle completed. Total peers banned: {len(all_to_ban)}")
                    except Exception as e:
                        logger.error(f"Failed to execute mass ban: {e}")
                else:
                    for ip_port, info, reason in all_to_ban:
                        logger.info(f"[DRY-RUN] [MATCH] {reason} | IP: {ip_port}")
                    logger.info(f"[DRY-RUN] Found {len(all_to_ban)} peers to ban.")

            consecutive_errors = 0
            
        except Exception as e:
            consecutive_errors += 1
            retry_delay = min(10 * consecutive_errors, 300)
            logger.error(f"Cycle execution error: {e}. Attempting recovery in {retry_delay} seconds...")
            time.sleep(retry_delay)
            
            try:
                qbt.auth_log_in()
            except Exception:
                pass
            continue
                
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting gracefully.")
        sys.exit(0)
