#!/usr/bin/env python3
import argparse
import logging
import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path

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

    "empty_client_mode": "strict",    # strict | smart | disabled

    "block_list": ['xunlei', 'xl00', 'thunder', 'xfwl', 'unknown', 'top-bt', 'torrent+'],

    "whitelist_ips": [
        "127.0.0.1", "192.168.", "10.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."
    ],

    "whitelist_clients": [
        "qBittorrent", "Transmission", "Deluge", "rtorrent", "BiglyBT", "PicoTorrent"
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
        config.update(loaded)
        print(f"Config loaded: {config_path}")
        return config
    except Exception as e:
        print(f"Error reading config {config_path}: {e}", file=sys.stderr)
        return DEFAULT_CONFIG.copy()


def save_default_config(config_path):
    if os.path.exists(config_path):
        return
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4, ensure_ascii=False)
        print(f"Created example of config file: {config_path}")
    except Exception:
        pass


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="qBittorrent Peer Guard: Automated anti anti-P2P utility",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument('--config', type=str, default='peer_guard.json',
                        help='Path to JSON config file (optional)')

    # Connection
    parser.add_argument('--host', type=str, default=None, help='Override host from config')
    parser.add_argument('--user', type=str, default=None, help='Override username')
    parser.add_argument('--pass', dest='password', type=str, default=None, help='Override password')

    # Operation
    parser.add_argument('--interval', type=float, default=None, help='Scan interval in seconds')
    parser.add_argument('--threshold', type=int, default=None, help='Upload threshold in bytes')
    parser.add_argument('--max-bans-per-cycle', type=int, default=None)

    parser.add_argument('--empty-client-mode', type=str, default=None,
                        choices=['strict', 'smart', 'disabled'])

    # Logging & Mode
    parser.add_argument('--log-file', type=str, default=None)
    parser.add_argument('--silent', action='store_true')
    parser.add_argument('--dry-run', action='store_true')

    return parser.parse_args()


def setup_logging(silent):
    handlers = [] if not silent else [logging.NullHandler()]
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )
    return logging.getLogger("PeerGuard")


def initialize_tabular_log(file_path):
    if not file_path or os.path.exists(file_path):
        return
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            header = f"{'DATE TIME':<16} | {'IP':<40} | {'FLAGS':<12} | {'PROG':<6} | {'UPLOADED':<10} | {'DOWNLOADED':<10} | {'REASON':<30} | CLIENT\n"
            f.write(header)
            f.write("-" * len(header) + "\n")
    except Exception as e:
        print(f"CRITICAL: Failed to initialize log file: {e}", file=sys.stderr)


def log_ban_to_tabular_file(file_path, info, reason):
    if not file_path:
        return
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        ip = info.get('ip', '0.0.0.0')
        flags = info.get('flags', '').strip()
        raw_progress = info.get('progress', 0.0)
        progress_str = f"{raw_progress:.1%}" if raw_progress <= 1.0 else f"{raw_progress}%"

        line = f"{timestamp:<16} | {ip:<40} | {flags:<12} | {progress_str:<6} | " \
               f"{info.get('uploaded', 0):<10} | {info.get('downloaded', 0):<10} | " \
               f"{reason:<30} | {info.get('client', '').strip()}\n"

        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(line)
    except:
        pass


def check_peer_rules(info, config, threshold):
    if not isinstance(info, dict):
        return False, ""

    client_name = str(info.get('client', '')).strip()
    client_lower = client_name.lower()
    flags = str(info.get('flags', ''))
    progress = float(info.get('progress', 0.0))
    uploaded = int(info.get('uploaded', 0))
    ip = info.get('ip', '')

    # Whitelist IP
    if any(ip.startswith(w) for w in config["whitelist_ips"]):
        return False, ""

    # Whitelist Client
    if any(w.lower() in client_lower for w in config["whitelist_clients"]):
        return False, ""

    # Block List
    if any(bot_tag in client_lower for bot_tag in config["block_list"]):
        return True, "BLACKLISTED_CLIENT"

    # Empty Client Mode
    if not client_name:
        mode = config["empty_client_mode"]
        if mode == "strict":
            return True, "EMPTY_CLIENT_STRICT"
        elif mode == "disabled":
            return False, ""
        else:  # smart
            if (progress == 0.0 and uploaded > 3 * 1024 * 1024) or uploaded > threshold * 0.4:
                return True, "EMPTY_CLIENT_SUSPICIOUS"
            return False, ""

    # Excessive upload with zero progress
    if uploaded > threshold and progress == 0.0:
        return True, "EXCESSIVE_UPLOAD_ZERO_PROGRESS"

    # Dead PEX / garbage connections
    is_dead = (progress == 0.0 and uploaded == 0 and 'S' not in flags and ('X' in flags or 'h' in flags))
    if is_dead:
        return True, "INACTIVE_PEX_CONN"

    return False, ""


def process_torrent_peers(qbt, torrent_hash, config, threshold, dry_run, log_file, logger):
    to_ban_list = []
    try:
        peer_data = qbt.sync_torrent_peers(torrent_hash)
        if not peer_data or 'peers' not in peer_data:
            return []
        peers = peer_data['peers']
    except Exception as e:
        logger.debug(f"Failed to fetch peers for {torrent_hash[:8]}...: {e}")
        return []

    for ip_port, info in peers.items():
        should_ban, reason = check_peer_rules(info, config, threshold)

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
                to_ban_list.append((ip_port, info, reason))

    return to_ban_list


def verify_connection(qbt, logger):
    try:
        qbt.auth_log_in()
        logger.info(f"Connected to qBittorrent v{qbt.app_version()}")
        return True
    except Exception as e:
        logger.critical(f"Connection failed: {e}")
        return False


def main():
    args = parse_arguments()
    config = load_config(args.config)
    save_default_config(args.config)

    if args.host:      config["host"] = args.host
    if args.user:      config["username"] = args.user
    if args.password:  config["password"] = args.password
    if args.interval is not None: config["interval"] = args.interval
    if args.threshold is not None: config["threshold"] = args.threshold
    if args.max_bans_per_cycle is not None:
        config["max_bans_per_cycle"] = args.max_bans_per_cycle
    if args.empty_client_mode:
        config["empty_client_mode"] = args.empty_client_mode

    logger = setup_logging(args.silent)

    logger.info("=== qBittorrent Peer Guard started ===")
    if args.dry_run:
        logger.info("DRY-RUN MODE ENABLED - no bans will be applied")

    if args.log_file:
        initialize_tabular_log(args.log_file)

    qbt = qbittorrentapi.Client(
        host=config["host"],
        username=config["username"],
        password=config["password"]
    )

    if not verify_connection(qbt, logger):
        sys.exit(1)

    consecutive_errors = 0

    while True:
        try:
            active_torrents = qbt.torrents_info(status_filter='active')
            all_to_ban = []

            for torrent in active_torrents:
                torrent_labels = [lbl.lower() for lbl in torrent.get('tags', '').split(',') if lbl]
                if any(ex_label in torrent_labels for ex_label in config["excluded_labels"]):
                    continue

                bans = process_torrent_peers(
                    qbt, torrent.hash, config, config["threshold"],
                    args.dry_run, args.log_file, logger
                )
                all_to_ban.extend(bans)

            if config["max_bans_per_cycle"] > 0 and len(all_to_ban) > config["max_bans_per_cycle"]:
                logger.warning(f"Too many bans ({len(all_to_ban)}), limiting to {config['max_bans_per_cycle']}")
                all_to_ban = all_to_ban[:config["max_bans_per_cycle"]]
            elif config["max_bans_per_cycle"] == 0:
                logger.debug("max_bans_per_cycle = 0 → no limit applied")

            if all_to_ban and not args.dry_run:
                ips_string = '|'.join([peer[0] for peer in all_to_ban])
                qbt.transfer_ban_peers(peers=ips_string)
                logger.info(f"Cleanup cycle completed. Total peers banned: {len(all_to_ban)}")

            consecutive_errors = 0

        except Exception as e:
            consecutive_errors += 1
            retry_delay = min(10 * consecutive_errors, 300)
            logger.error(f"Cycle error: {e}. Retrying in {retry_delay}s...")
            time.sleep(retry_delay)
            try:
                qbt.auth_log_in()
            except:
                pass
            continue

        time.sleep(config["interval"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nPeer Guard stopped by user.")
        sys.exit(0)
