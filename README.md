**qBittorrent Peer Guard**

A lightweight, automated Python tool that cleans up your qBittorrent client by filtering out malicious, parasitic, and useless peers — such as Xunlei/Thunder clients, zero-progress leechers, and dead PEX connections.

### Key Features

- **Smart Peer Filtering**: Automatically detects and blocks bad peers based on strict but fair rules.
- **Clean Tabular Logging**: Saves blocked peers to a nicely formatted log file (easy to read in any text editor).
- **Dry-Run Mode** (`--dry-run`): Safely preview what will be blocked without actually banning anyone.
- **Silent Mode** (`--silent`): Perfect for running in the background with cron, systemd, or screen.

### Installation

**Requirements:**
- Python 3.8 or higher
- `qbittorrent-api` library

```bash
git clone https://github.com/cat658011/some-qb-stuff.git
cd some-qb-stuff
pip install qbittorrent-api
```

Make sure **Web UI** is enabled in qBittorrent (Tools → Options → Web UI).

### Usage

```bash
python3 block-sus-peers.py [options]
```

You can configure everything via command-line flags or environment variables.

#### Main Options

| Flag              | Description                                      | Default                  |
|-------------------|--------------------------------------------------|--------------------------|
| `--host`          | qBittorrent WebUI address                        | `127.0.0.1:8080`         |
| `--user`          | WebUI username                                   | `admin`                  |
| `--pass`          | WebUI password                                   | —                        |
| `--interval`      | Scan interval (seconds)                          | 2.0                      |
| `--threshold`     | Upload limit for 0% progress peers (bytes)       | 50 MB                    |
| `--log-file`      | Path to log file                                 | None (disabled)          |
| `--silent`        | Disable console output                           | False                    |
| `--dry-run`       | Simulation mode (no actual bans)                 | False                    |

### Examples

**1. Basic run with logging**
```bash
python3 block-sus-peers.py --host 127.0.0.1:8087 --user admin --pass secret123 --interval 2.5 --log-file "./peers_base.txt"
```

**2. Safe testing (highly recommended first)**
```bash
python3 block-sus-peers.py --dry-run
```

**3. Headless / Server mode (using environment variables)**
```bash
export QBT_USER="your_username"
export QBT_PASS="your_password"

python3 block-sus-peers.py --host 10.0.0.5:8080 --interval 3 --log-file "/var/log/peer_guard.log" --silent
```

### Log Example

```text
DATE TIME       | IP                      | FLAGS | PROG   | UPLOADED   | DOWNLOADED | REASON                          | CLIENT
----------------|-------------------------|-------|--------|------------|------------|---------------------------------|--------------------
2026-05-16 00:18 | 117.84.128.123         | H X   | 0.0%   | 0 B        | 0 B        | BLACKLISTED_CLIENT              | Xunlei 11.2.1
2026-05-16 00:18 | 2803:f340:...          | H     | 0.0%   | 154 MB     | 0 B        | EXCESSIVE_UPLOAD_ZERO_PROGRESS  | FakeClient v1
```

### Filtering Rules

The script blocks peers based on these criteria:

1. **EMPTY_CLIENT_NAME** — Peers with no client name (hidden/stripped).
2. **BLACKLISTED_CLIENT** — Known bad clients (Xunlei, Thunder, xfwl, top-bt, etc.).
3. **EXCESSIVE_UPLOAD_ZERO_PROGRESS** — Leechers that download a lot from you but stay at 0% progress/or not uploads anything.
4. **INACTIVE_PEX_CONN** — Dead/stale Peer Exchange connections that waste slots.

Note: Rules #1 and #4 are especially effective at catching Anti-P2P organization bots.

### Why This Tool Exists
Popular torrents are often flooded with bots, fake clients, and anti-P2P scrapers. They eat up your connection limits and upload slots while giving almost nothing back.

In real-world testing, this script removed **over 14,000** junk peers in just 30 minutes. The result? Much cleaner connection queue, more stable speeds, and better connections with real peers.

AIAIAIAIAI generated