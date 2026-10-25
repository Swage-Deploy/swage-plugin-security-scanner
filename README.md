<p align="center">
    <img src="https://raw.githubusercontent.com/Swage-Deploy/swage-core/main/public/favicon.svg" width="72" height="72" alt="Swage">
</p>

<h1 align="center">Security scanner for Swage</h1>

<p align="center">
    Find brute force attempts and probing in your servers' logs, and block the addresses behind them.
    <br>
    <a href="https://swagedeploy.app"><strong>swagedeploy.app</strong></a> · <a href="https://swagedeploy.app/docs/security">Documentation</a>
</p>

---

Reads each server's SSH, sudo and nginx access logs every few minutes, counts brute force attempts and probing, raises alerts about SSH logins, and lets you block addresses in the server's firewall. It can also install fail2ban, which bans the addresses behind brute force attempts and probing.

The scanner is turned on per server, from the server's **Plugins** tab.

## Requirements

- Swage `v1.0.0` or later
- Ubuntu servers with `ufw`, which Swage sets up when it provisions them

## Installation

1. **Install the plugin** from the **Available** list on Swage's **Plugins** page, where it's listed as Security scanner. Swage installs the newest version, rebuilds itself with it, and runs the plugin's migrations.

   From the Swage host instead:

   ```bash
   sudo -u swage php /home/swage/app/current/artisan swage:plugin:install swage/security-scanner
   ```

2. **Turn it on** for each server under **Servers → *server* → Plugins → Security scanner**.

3. Optionally, **install fail2ban** from the same panel. It bans an address:

   - from SSH for an hour after five failed logins in ten minutes,
   - from the server's sites for an hour after 20 probes for vulnerable files (see below) in an hour,
   - and from everything for a week once it has been banned three times in a day.

   Servers without nginx don't get the probes ban. If fail2ban was installed by an earlier version of the plugin, the panel offers **Update fail2ban** to add it.

## What it looks for

The scanner counts failed and unknown-user SSH logins, failed sudo attempts, site login form submissions, denied requests, and probes for vulnerable files: requests for paths such as `/.env`, `/.git`, `/wp-login.php`, `/vendor/phpunit` or a PHP script other than `index.php`. These show in the panel's totals and busiest addresses, and fail2ban bans the addresses behind repeated SSH failures and probing.

Only SSH logins raise alerts:

| Alert | Severity | Raised when |
|---|---|---|
| SSH login from an address that was failing to log in | High | An address logs in over SSH after failing to log in during the previous day. |
| SSH login from a new address | Low | Someone logs in over SSH from an address the server hasn't been logged into from before. Logins found by the first scan become the known addresses. |

Events from Cloudflare's own addresses aren't counted. nginx logs them for requests it can't take a visitor's address from, such as ones for a hostname no site serves, and blocking one would cut off every visitor Cloudflare routes through it.

Each rule keeps at most one open alert per address. Further activity counts on that alert, and a new alert only opens after the earlier one is resolved. Swage's own SSH logins aren't counted: the scanner learns the address Swage connects from on each scan.

The panel also shows totals for the last 24 hours, the ten busiest hostile addresses, the addresses blocked in the firewall, and whether fail2ban is installed. Addresses fail2ban has banned, in its `sshd`, `swage-probes` or `recidive` jail, are listed under fail2ban with what they did in the last 24 hours, rather than among the busiest addresses. Alerts about an address fail2ban has banned, or that is blocked, are left out of the open alerts while the ban or block lasts.

### Banning probes with fail2ban

The `swage-probes` jail reads every access log in `/var/log/nginx` and matches each request's path against the same patterns the scanner counts as probes. Cloudflare's addresses are never banned. When a new site's access log appears, the next scan reloads the jail so fail2ban reads it too.

Its bans, and the week long `recidive` bans, are applied in two places, like blocking an address:

- **The firewall**, on ports 80 and 443 for `swage-probes` and every port for `recidive`.
- **nginx**, with a `deny <address>;` line in `/etc/nginx/conf.d/swage-fail2ban-<jail>.conf`, followed by a reload. Visitors to sites proxied by Cloudflare connect from Cloudflare's addresses, so the firewall never sees them, but nginx takes the visitor's address from Cloudflare's header and gives them a 403.

Each jail keeps its own file, so an hour's ban ending doesn't lift a week's ban of the same address. fail2ban empties the files when it stops and fills them again when it starts. nginx is only reloaded when its config passes `nginx -t`.

## How logs are read

Swage connects over SSH, as it does for everything else. No agent is installed, and no port is opened.

- **SSH and sudo** are read from the systemd journal, after the cursor where the last scan stopped. The first scan reads the last 15 minutes.
- **nginx access logs** (`/var/log/nginx/*access.log`, the server's own and every site's) are read from the byte offset where the last scan stopped. When logrotate replaces a log, its inode changes and the new file is read from the top. A log seen for the first time is read back 256 KB. A log that grew by more than 2 MB since the last scan catches up over the next few scans.

Only counts are stored: one row per kind of event, address, log and hour, plus the first 20 distinct usernames or paths involved. Whole log lines never leave the server. Counted events are kept for 14 days. Resolved alerts are kept for 90 days after they're resolved.

Log lines contain text that attackers choose, such as request paths and usernames. Each section of the scan's output starts with a marker generated fresh for every scan, so a log line can't pose as another section.

### Limits

- Lines written to an access log between the last scan and its rotation aren't read, which is at most a few minutes of one log per day.
- On servers that accept SSH passwords, one failed password can be logged as both a failed password and a closed connection, and is counted twice.

## Blocking addresses

**Block** on an alert or on one of the busiest addresses, or **Block address** on the blocked addresses panel, blocks the address in two places:

- **The firewall**, with a rule ahead of the firewall's others, which stops it reaching SSH and any site it reaches directly:

  ```bash
  ufw prepend deny from <address> comment 'Blocked by Swage security scanner'
  ```

- **nginx**, with a `deny <address>;` line in `/etc/nginx/conf.d/swage-security-scanner-blocked.conf`, which every site inherits, followed by a reload. Visitors to a site proxied by Cloudflare connect from Cloudflare's addresses, so the firewall never sees them. nginx takes the visitor's address from Cloudflare's header before it applies its deny list, so they get a 403. Servers without nginx, such as database servers, only get the firewall rule.

Blocking and unblocking show in the server's activity log. Each scan checks the nginx deny list and blocks again any blocked address missing from it, such as addresses blocked by older versions of the plugin.

The scanner refuses to block an address in Cloudflare's ranges, the address Swage connects to the server from, or the address you're using Swage from.

## Configuration

These can be set in Swage's `.env`:

| Variable | Default | Meaning |
|---|---|---|
| `SECURITY_SCANNER_INTERVAL` | `2` | Minutes between scans of each server. |
| `SECURITY_SCANNER_RETENTION_DAYS` | `14` | Days of counted events to keep. |
| `SECURITY_SCANNER_HTTP_PROBES` | `20` | Probes from one address in an hour before fail2ban bans it from the sites. Servers pick up a change when fail2ban is installed or updated. |

Scans run on Swage's queue, one at a time per server, and aren't recorded in the server's activity log.

## Extending

Each new alert dispatches `Swage\SecurityScanner\Events\AlertRaised`, carrying the `SecurityAlert`. Further occurrences on an open alert don't dispatch it again. Listen for it to send notifications, or to pass the alert and its server's recent `SecurityEvent` counts to an analysis step.

## Updating

Swage's **Plugins** page shows when a newer version is available. Update from there, or on the Swage host:

```bash
sudo -u swage php /home/swage/app/current/artisan swage:plugin:update swage/security-scanner
```

## Development

The plugin implements Swage's server integration contract (`App\Servers\ServerIntegration`), version 1, so it runs inside a Swage install rather than on its own.

`tests/SecurityScannerPluginTest.php` is a Pest test that runs inside a Swage checkout: it uses Swage's models, factories and test helpers. To run it:

1. Add this plugin's `src` directory to the Swage checkout's `autoload-dev` as `Swage\\SecurityScanner\\`.
2. Run `composer dump-autoload`.
3. Copy the test into Swage's `tests/Feature`.
4. Run `php artisan test --filter=SecurityScannerPluginTest`.

The test runs the plugin's migrations itself.

## License

Copyright (c) 2026 Node Dog Consulting. Released under the [MIT License](LICENSE).
