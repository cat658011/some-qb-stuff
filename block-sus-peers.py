#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import time
import json
from datetime import datetime

try:
    import qbittorrentapi
except ImportError:
    sys.exit("CRITICAL: 'qbittorrentapi' module is not installed. Please run: pip install qbittorrent-api")

# ====================== DEFAULT CONFIG ======================
DEFAULT_CONFIG = {
    "host": "127.0.0.1:8080",
    "username": "admin",
    "password": "",

    "interval": 2.5,
    "threshold": 52428800,
    "max_bans_per_cycle": 0,

    "anti_leech": True,      
    "min_ratio": 0.05,       
    "empty_client_mode": "strict", # strict | smart | disabled

    "block_list": ['xunlei', 'xl00', 'thunder', 'xfwl', 'unknown', 'top-bt', 'torrent+'],

    "whitelist_ips": [
        "127.0.0.1", "192.168.", "10.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
    ],

    "whitelist_clients": [
        "qBittorrent", "Transmission", "Deluge", "rtorrent", "BiglyBT", "PicoTorrent", "libtorrent"
    ],

    "excluded_labels": ["private", "no-guard", "trusted", "whitelist", "important"]
}


def load_config(config_path):
    if not config_path or not os.path.exists(config_path):
        return DEFAULT_CONFIG.copy()
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            loaded = json.load(f)
        config = DEFAULT_CONFIG.copy()
        config.update(loaded) # Deep override
        return config
    except Exception as e:
        print(f"Error reading config: {e}", file=sys.stderr)
        return DEFAULT_CONFIG.copy()


def save_default_config(config_path, config_data):
    if os.path.exists(config_path):
        return
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=4, ensure_ascii=False)
        print(f"Created default config file: {config_path}")
    except Exception as e:
        print(f"Failed to create config file: {e}", file=sys.stderr)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="qBittorrent Peer Guard: Automated Anti-Leech & Peer Management Utility",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    prot = parser.add_argument_group('Protection Settings')
    prot.add_argument('--anti-leech', action='store_true', default=None, 
                      help='Enable aggressive anti-leech protection')
    prot.add_argument('--threshold', type=int, help='Upload threshold in bytes before ban logic triggers')
    prot.add_argument('--ratio', type=float, dest='min_ratio', help='Min ratio (DL/UP) required')

    conn = parser.add_argument_group('Connection Settings')
    conn.add_argument('--host', type=str, help='qBittorrent WebUI host')
    conn.add_argument('--user', type=str, help='WebUI Username')
    conn.add_argument('--pass', dest='password', type=str, help='WebUI Password')

    general = parser.add_argument_group('General')
    general.add_argument('--config', type=str, default='peer_guard.json', help='Path to config file')
    general.add_argument('--dry-run', action='store_true', help='Scan and log, but do not actually ban peers')
    general.add_argument('--log-file', type=str, default='bans.log', help='Path to tabular log file')

    return parser.parse_args()


def initialize_tabular_log(file_path):
    if not file_path or os.path.exists(file_path): return
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            header = f"{'DATE TIME':<18} | {'IP ADDRESS':<22} | {'PROG':<6} | {'UP (MB)':<8} | {'DOWN (MB)':<9} | {'REASON':<22} | CLIENT\n"
            f.write(header + "-" * len(header) + "\n")
    except Exception as e:
        print(f"Failed to initialize log file: {e}", file=sys.stderr)


def log_ban_to_file(file_path, ip, info, reason):
    if not file_path: return
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        raw_progress = float(info.get('progress', 0.0))
        progress_str = f"{raw_progress:.1%}" if raw_progress <= 1.0 else f"{raw_progress}%"
        
        uploaded_mb = info.get('uploaded', 0) / 1048576
        downloaded_mb = info.get('downloaded', 0) / 1048576
        client = info.get('client', 'Unknown').strip()[:30]
        line = f"{timestamp:<18} | {ip:<22} | {progress_str:<6} | {uploaded_mb:<8.1f} | {downloaded_mb:<9.1f} | {reason:<22} | {client}\n"
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(line)
    except:
        pass


def check_peer_rules(info, config, is_seeding):
    if not isinstance(info, dict):
        return False, ""

    client_name = str(info.get('client', '')).strip()
    client_lower = client_name.lower()
    uploaded = int(info.get('uploaded', 0))
    downloaded = int(info.get('downloaded', 0))
    progress = float(info.get('progress', 0.0))
    ip = str(info.get('ip', ''))
    flags = str(info.get('flags', ''))

    if any(ip.startswith(w) for w in config["whitelist_ips"]): return False, ""
    if any(w.lower() in client_lower for w in config["whitelist_clients"]): return False, ""

    if any(bot_tag in client_lower for bot_tag in config["block_list"]):
        return True, "BLACKLISTED_CLIENT"

    if config.get("anti_leech"):
        if uploaded > config["threshold"]:
            if not is_seeding:
                # Если мы качаем, мы ждем отдачи от других
                if progress == 0.0:
                    return True, "LEECH_ZERO_PROGRESS"
                
                peer_ratio = downloaded / max(uploaded, 1)
                if peer_ratio < config.get("min_ratio", 0.05):
                    return True, "LEECH_LOW_RATIO"
            else
                if progress == 0.0 and uploaded > (config["threshold"] * 3):
                    return True, "LEECH_VAMPIRE"

    if not client_name:
        mode = config["empty_client_mode"]
        if mode == "strict": 
            return True, "EMPTY_CLIENT_STRICT"
        if mode == "smart" and uploaded > (config["threshold"] / 2):
            return True, "EMPTY_CLIENT_SUSPICIOUS"

    if progress == 0.0 and uploaded == 0 and downloaded == 0 and 'S' not in flags and ('X' in flags or 'h' in flags):
        return True, "GHOST_CONNECTION"

    return False, ""


def main():
    args = parse_arguments()
    config = load_config(args.config)

    # CLI overrides
    if args.anti_leech is not None: config["anti_leech"] = args.anti_leech
    if args.threshold: config["threshold"] = args.threshold
    if args.min_ratio: config["min_ratio"] = args.min_ratio
    if args.host: config["host"] = args.host
    if args.user: config["username"] = args.user
    if args.password: config["password"] = args.password

    save_default_config(args.config, config)

    # Setup Logging
    logging.basicConfig(
        level=logging.INFO, 
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger("PeerGuard")

    if args.log_file and not args.dry_run:
        initialize_tabular_log(args.log_file)

    logger.info(f"=== qBittorrent Peer Guard Started ===")
    logger.info(f"Mode: {'DRY-RUN' if args.dry_run else 'ACTIVE'} | Anti-Leech: {'ON' if config['anti_leech'] else 'OFF'}")

    qbt = qbittorrentapi.Client(host=config["host"], username=config["username"], password=config["password"])
    
    try:
        qbt.auth_log_in()
        logger.info(f"Connected to qBittorrent v{qbt.app_version()} (API v{qbt.api_version})")
    except Exception as e:
        logger.critical(f"Initial login failed: {e}")
        sys.exit(1)

    consecutive_errors = 0

    while True:
        try:
            active_torrents = qbt.torrents_info(status_filter='active')
            to_ban_ips = set()
            for torrent in active_torrents:
                tags = [t.strip().lower() for t in torrent.get('tags', '').split(',') if t]
                if any(ex in tags for ex in config["excluded_labels"]):
                    continue

                is_seeding = (torrent.get('progress', 0.0) == 1.0)

                try:
                    peer_data = qbt.sync_torrent_peers(torrent.hash)
                    peers = peer_data.get('peers', {})
                except Exception as e:
                    logger.debug(f"Failed to fetch peers for torrent {torrent.hash[:8]}: {e}")
                    continue

                for peer_id, info in peers.items():
                    should_ban, reason = check_peer_rules(info, config, is_seeding)
                    
                    if should_ban:
                        pure_ip = info.get('ip')
                        if not pure_ip:
                            pure_ip = peer_id.split(':')[0] if peer_id.count(':') == 1 else peer_id

                        if pure_ip not in to_ban_ips:
                            client = info.get('client', 'Unknown').strip()
                            if args.dry_run:
                                logger.info(f"[DRY-RUN] Would ban: {pure_ip:<15} | Reason: {reason:<20} | Client: {client}")
                            else:
                                logger.warning(f"[BAN] IP: {pure_ip:<15} | Reason: {reason:<20} | Client: {client}")
                                log_ban_to_file(args.log_file, pure_ip, info, reason)
                            
                            to_ban_ips.add(pure_ip)

            if to_ban_ips and not args.dry_run:
                ban_list = list(to_ban_ips)
                limit = config.get("max_bans_per_cycle", 0)
                
                if limit > 0 and len(ban_list) > limit:
                    logger.warning(f"Ban list too large ({len(ban_list)}), truncating to {limit} to protect API.")
                    ban_list = ban_list[:limit]

                qbt.transfer_ban_peers(peers='|'.join(ban_list))
                logger.info(f"Cycle finished. Applied {len(ban_list)} bans.")

            consecutive_errors = 0

        except qbittorrentapi.APIConnectionError:
            logger.error("Connection lost. Attempting to re-authenticate...")
            try:
                qbt.auth_log_in()
                logger.info("Re-authentication successful.")
            except Exception:
                pass 
        except Exception as e:
            consecutive_errors += 1
            retry_delay = min(15 * consecutive_errors, 300)
            logger.error(f"Unexpected error in loop: {e}. Retrying in {retry_delay}s...")
            time.sleep(retry_delay)
            continue

        time.sleep(config["interval"])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Peer Guard stopped by user. Exiting safely.")
        sys.exit(0)
