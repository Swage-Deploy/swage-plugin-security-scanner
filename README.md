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

Reads each server's SSH, sudo and nginx access logs every few minutes, counts brute force attempts and probing, raises alerts about SSH logins, and lets you block addresses in the server's firewall. It can also install fail2ban, which bans the addresses behind brute force attempts and probing, and have an AI model review each server's security and suggest what to fix.

The scanner is turned on per server, from the server's **Plugins** tab.

## Requirements

- Swage `v1.0.1` or later. The [AI review](#ai-review) needs Swage `v1.3.0`, which added plugin settings.
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

   Servers without nginx don't get the probes ban. No jail ever bans the address Swage connects from, so failed logins or probes from it cannot lock Swage out. The address is taken from Swage's SSH connection when fail2ban is installed. If fail2ban was installed by an earlier version of the plugin, without the probes ban or without leaving Swage's address alone, the panel offers **Update fail2ban**.

## What it looks for

The scanner counts failed and unknown-user SSH logins, failed sudo attempts, site login form submissions, denied requests, and probes for vulnerable files: requests for paths such as `/.env`, `/.git`, `/wp-login.php`, `/vendor/phpunit` or a PHP script other than `index.php`. These show in the panel's totals and busiest addresses, and fail2ban bans the addresses behind repeated SSH failures and probing.

Only SSH logins raise alerts:

| Alert | Severity | Raised when |
|---|---|---|
| SSH login from an address that was failing to log in | High | An address logs in over SSH after failing to log in during the previous day. |
| SSH login from a new address | Low | Someone logs in over SSH from an address the server hasn't been logged into from before. Logins found by the first scan become the known addresses. |

Events from Cloudflare's own addresses aren't counted. nginx logs them for requests it can't take a visitor's address from, such as ones for a hostname no site serves, and blocking one would cut off every visitor Cloudflare routes through it.

Each rule keeps at most one open alert per address. Further activity counts on that alert, and a new alert only opens after the earlier one is resolved. Swage's own SSH logins aren't counted: the scanner learns the address Swage connects from on each scan.

The panel also shows totals for the last 24 hours, the busiest hostile addresses, the addresses blocked in the firewall, and whether fail2ban is installed. Each table shows ten rows a page. Addresses fail2ban has banned, in its `sshd`, `swage-probes` or `recidive` jail, are listed under fail2ban with what they did in the last 24 hours, rather than among the busiest addresses. Alerts about an address fail2ban has banned, or that is blocked, are left out of the open alerts while the ban or block lasts.

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

## AI review

The AI review has an AI model look over each server it's turned on for and suggest what to fix. It works with any OpenAI compatible chat completions API, such as OpenAI, OpenRouter, or a local Ollama or vLLM, through [Laravel AI](https://github.com/laravel/ai).

**It only reads and suggests.** The model gets no tools and no access to the server. Swage gathers what it reviews and sends it as text, and the only thing the review writes is its findings, to Swage's database. Nothing the model suggests is ever run. A person decides what to do, and the panel's own actions, such as blocking an address or installing fail2ban, still need someone to click them.

To set it up:

1. On Swage's **Plugins** page, open the **Server** tab and **Configure Security scanner**. Enter:
   - **API URL**: the base URL of the API, ending before `/chat/completions`, such as `https://api.openai.com/v1`.
   - **API key**: sent as a bearer token. It's stored encrypted, and can be left blank for APIs that don't need one.
   - **Model**: the model to use. It must reply in JSON reliably. The review asks for a JSON schema response and also spells the schema out in its instructions, since some APIs, such as Ollama's, ignore the requested format. A reply that isn't that JSON fails the review rather than showing as clean.
2. Turn on **Review this server with AI** in each server's Security scanner panel. The first review runs straight away. Then each server is reviewed every 6 hours, or whenever someone clicks **Review now**.

Each review sends the API:

- what the scanner recorded: event totals for the last day and each of the last 7 days, the 25 busiest hostile addresses with a few of the usernames or paths each tried, open alerts, blocked addresses and fail2ban's state,
- a snapshot of how the server is set up, read by a fixed script that only runs read-only commands: the OS and kernel, whether a reboot is required, packages with pending updates, whether automatic updates are on, the effective `sshd` settings, listening ports, `ufw status`, accounts that can log in, how many authorized SSH keys each has, passwordless sudo rules, failed systemd units and recent logins.

That includes IP addresses and account names, so only use an API you trust with them. The script runs over Swage's existing SSH connection, like a scan does. The model can't change it or add to it. The plugin's tests check that the script only runs commands that read, and never writes a file.

The panel shows the latest review: a short summary, then each finding with its severity, what was seen and a suggestion. Suggestions can include shell commands. They come from a model and can be wrong, so check them before acting. Usernames and paths in the logs can be chosen by attackers, and the model is told to treat everything it's given as data, not instructions.

### Checking a review read the server

A review that finds nothing should still show that it looked. Each review shows:

- **Checked**: what the model says it looked at, one line per part of the snapshot and of the scanner's records, with what it saw, such as "SSH settings: password logins off, root login key only". The model is told to list these even when nothing needs attention. If a review has none, the panel says there's no sign it read the server.
- **The model and tokens**: the model you set, the model the API reports it used if that's different, and how many tokens it read and wrote. A review of a busy server that read only a few hundred tokens didn't get much.
- **Parts that couldn't be read**: each part of the snapshot says when its command failed or isn't installed, as opposed to running and finding nothing. If any couldn't be read, the panel lists them, since anything wrong there wasn't checked.
- **What was sent**: the exact data the model was given, for people who can manage the server. It includes the server's accounts and sudo rules, so viewers don't see it.

To test a model before trusting a clean review, set up something it should flag on a test server, such as a service listening on a public port or `PermitRootLogin yes`, and click **Review now**.

A review that fails shows its error in the panel, and isn't tried again until the next review is due. Reviews are kept for 30 days and aren't recorded in the server's activity log.

## Configuration

These can be set in Swage's `.env`:

| Variable | Default | Meaning |
|---|---|---|
| `SECURITY_SCANNER_INTERVAL` | `2` | Minutes between scans of each server. |
| `SECURITY_SCANNER_RETENTION_DAYS` | `14` | Days of counted events to keep. |
| `SECURITY_SCANNER_HTTP_PROBES` | `20` | Probes from one address in an hour before fail2ban bans it from the sites. Servers pick up a change when fail2ban is installed or updated. |
| `SECURITY_SCANNER_AI_INTERVAL_HOURS` | `6` | Hours between AI reviews of each server. |
| `SECURITY_SCANNER_AI_TIMEOUT` | `120` | Seconds to wait for the API to answer. |
| `SECURITY_SCANNER_AI_RETENTION_DAYS` | `30` | Days of AI reviews to keep. |

The AI review's API URL, key and model are set on the plugin's **Configure** page instead.

Scans and AI reviews run on Swage's queue, one of each at a time per server, and aren't recorded in the server's activity log.

## Extending

Each new alert dispatches `Swage\SecurityScanner\Events\AlertRaised`, carrying the `SecurityAlert`. Further occurrences on an open alert don't dispatch it again. Listen for it to send notifications, or to pass the alert and its server's recent `SecurityEvent` counts to an analysis step.

## Updating

Swage's **Plugins** page shows when a newer version is available. Update from there, or on the Swage host:

```bash
sudo -u swage php /home/swage/app/current/artisan swage:plugin:update swage/security-scanner
```

## Development

The plugin implements Swage's server integration contract (`App\Servers\ServerIntegration`), version 1, so it runs inside a Swage install rather than on its own.

`tests/SecurityScannerPluginTest.php` and `tests/SecurityScannerAiReviewTest.php` are Pest tests that run inside a Swage checkout: they use Swage's models, factories and test helpers. To run them:

1. Add this plugin's `src` directory to the Swage checkout's `autoload-dev` as `Swage\\SecurityScanner\\`, and run `composer require laravel/ai:^1.3`.
2. Run `composer dump-autoload`.
3. Copy the tests into Swage's `tests/Feature`.
4. Run `php artisan test --filter=SecurityScanner`.

The test runs the plugin's migrations itself.

## License

Copyright (c) 2026 Node Dog Consulting. Released under the [MIT License](LICENSE).
