# Telegram 42-Check Web Security Audit Bot

## Features

- `/scan https://example.com`
- Also accepts a URL sent directly as a message.
- Runs 42 audit categories.
- Generates a PDF after every completed scan.
- PDF records the Telegram user who generated the audit.
- PDF ends with the configured developer name.
- Active security-test slots are disabled by default.

## Important authorization rule

Do not use active penetration testing against websites you do not own or have written permission to test.

Set `AUTHORIZED_USERS` to comma-separated Telegram numeric user IDs to allow the authorization-gated active-test slots.

## Local setup

1. Create a Telegram bot with BotFather and obtain the bot token.
2. Install Python 3.10+.
3. Run:

   `pip install -r requirements.txt`

4. Set environment variables:

   `BOT_TOKEN=YOUR_TOKEN`

   `DEV_NAME=YOUR DEV NAME`

   `AUTHORIZED_USERS=123456789`

5. Start:

   `python telegram.py`

6. In Telegram:

   `/scan https://example.com`

The generated PDF is also stored in `reports/`.

## Render

Create a new Render Background Worker from this repository/ZIP.

Build command:

`pip install -r requirements.txt`

Start command:

`python telegram.py`

Environment variables:

- `BOT_TOKEN` = Telegram bot token
- `DEV_NAME` = name printed at the end of each PDF
- `AUTHORIZED_USERS` = comma-separated numeric Telegram IDs authorized for active-test slots
- `MAX_CONCURRENT` = optional, default 2

## Notes

Some categories are intentionally implemented as passive checks or informational placeholders where reliable third-party databases or a controlled penetration-testing engine would be required. The bot does not claim a vulnerability merely because a check could not be performed.


## Local TCP port scanner

The port scanner uses Python TCP sockets directly from the machine running the bot. It does not require Shodan, VirusTotal, SecurityTrails, or another external scanning API.

Optional environment variables:

- `PORT_TIMEOUT` — TCP connection timeout in seconds; default `1.5`
- `PORT_WORKERS` — maximum concurrent probes; default `20`
- `PORTS` — comma-separated TCP ports; maximum 200 ports in this build

The PDF includes every tested port as `OPEN`, `CLOSED`, or `FILTERED/UNKNOWN`. A timeout cannot prove that a firewall is filtering a port, so the scanner intentionally uses `FILTERED/UNKNOWN` rather than claiming certainty.

Only scan systems you own or have explicit permission to test.


### Slow-site / rate-limit protection

The scanner spaces HTTP requests with a small delay and random jitter, then retries temporary responses such as `429`, `502`, `503`, and `504` using exponential backoff.

Configure:

- `REQUEST_DELAY=0.35` — minimum delay between requests
- `REQUEST_JITTER=0.15` — extra random delay
- `REQUEST_RETRIES=2` — retry count
- `REQUEST_BACKOFF=1.5` — backoff base in seconds
- `REQUEST_TIMEOUT=10` — per-request timeout

For a very slow site, increase `REQUEST_DELAY` to `0.75` or `1.0`.


### Expanded backup/sensitive-file checks

The backup-file scan checks additional common archive, database-dump, old-copy,
configuration-backup, source/archive, and version-control paths. It records
HTTP status without downloading the potentially sensitive files.


### Expanded management and cPanel discovery
The audit checks common admin/control-panel paths, cPanel/WHM/Webmail standard ports (2082/2083/2086/2087/2095/2096), and common panel hostnames such as cpanel, whm, webmail, and mail. It reports observed HTTP status codes and TCP states without attempting panel authentication or state-changing actions.
