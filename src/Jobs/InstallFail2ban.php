<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Models\Server;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\CloudflareAddresses;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\TrustedAddress;

/**
 * Installs fail2ban to ban addresses for good once they fail to log in over SSH ten times in a day, counted over a day
 * so attackers who pace their guesses are caught too.
 *
 * On servers with nginx it also bans addresses for good from the sites once they probe for vulnerable files five times
 * in a day, using the scanner's own probe patterns. Bans from the probes and recidive jails
 * are also denied in nginx, which takes the visitor's address from Cloudflare, so visitors to sites proxied by
 * Cloudflare are banned too. Running it again updates the jails.
 *
 * Swage's own address is never banned, since that would lock Swage out of the server. It is taken from the SSH
 * connection the install runs over, as well as the address the scanner last saw Swage connect from. The addresses
 * people trust on the server are never banned either.
 */
class InstallFail2ban implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    /**
     * The jail that bans addresses probing sites for vulnerable files.
     */
    public const string PROBES_JAIL = 'swage-probes';

    /**
     * The action that denies a jail's bans in nginx, each jail in its own file so one jail's unban leaves another's
     * ban in place.
     */
    public const string NGINX_ACTION = 'swage-nginx-deny';

    /**
     * Stands in for Swage's address in the jails until the install script fills it in from its SSH connection.
     */
    public const string PANEL_ADDRESS = '@SWAGE_PANEL_ADDRESS@';

    public int $timeout = 600;

    public int $tries = 1;

    public function __construct(public Server $server) {}

    public function uniqueId(): string
    {
        return (string) $this->server->id;
    }

    /**
     * Execute the job.
     */
    public function handle(RunServerTask $runTask): void
    {
        $port = (int) $this->server->ssh_port;
        $jail = self::PROBES_JAIL;
        $probesJail = $this->probesJail();
        $probesFilter = $this->probesFilter();
        $action = self::NGINX_ACTION;
        $nginxAction = $this->nginxAction();
        $panelAddress = self::PANEL_ADDRESS;
        $ignore = self::ignoreList($this->server);
        $sshRetry = (int) config('security-scanner.fail2ban_ssh');

        $runTask->run($this->server, 'Installing fail2ban', <<<BASH
        set -Eeuo pipefail

        export DEBIAN_FRONTEND=noninteractive

        # This runs over Swage's SSH connection, so the address it comes from is Swage's.
        panel_address=\${SSH_CLIENT%% *}
        [[ "\$panel_address" =~ ^[0-9A-Fa-f:.]+$ ]] || panel_address=''

        apt-get update -q
        apt-get install -yq -o DPkg::Lock::Timeout=300 fail2ban

        cat > /etc/fail2ban/jail.d/swage.conf <<'CONF'
        [DEFAULT]
        ignoreip = {$ignore}
        bantime = 1h
        findtime = 10m
        maxretry = 5
        backend = systemd

        # Attackers pace their guesses to stay under a jail's limit, so SSH failures are counted over a day, and the
        # addresses behind them are banned for good. fail2ban keeps permanent bans in its database across restarts.
        [sshd]
        enabled = true
        port = {$port}
        findtime = 1d
        maxretry = {$sshRetry}
        bantime = -1

        # recidive reads the bans fail2ban writes to its own log file, which isn't in the journal.
        [recidive]
        enabled = true
        backend = auto
        bantime = 1w
        findtime = 1d
        maxretry = 3
        CONF
        sed -i "s/{$panelAddress}/\$panel_address/" /etc/fail2ban/jail.d/swage.conf

        # fail2ban won't start with a jail that has no logs, so servers without nginx don't get the probes jail.
        if compgen -G '/var/log/nginx/*access.log' > /dev/null; then
        cat > /etc/fail2ban/action.d/{$action}.conf <<'CONF'
        {$nginxAction}
        CONF
        cat > /etc/fail2ban/filter.d/{$jail}.conf <<'CONF'
        {$probesFilter}
        CONF
        cat > /etc/fail2ban/jail.d/{$jail}.conf <<'CONF'
        {$probesJail}
        CONF
        sed -i "s/{$panelAddress}/\$panel_address/" /etc/fail2ban/jail.d/{$jail}.conf
        else
            rm -f /etc/fail2ban/jail.d/{$jail}.conf
        fi

        systemctl enable fail2ban
        systemctl restart fail2ban

        echo "fail2ban is installed."
        BASH);

        ScannerState::for($this->server)->update(['fail2ban_installed' => true, 'fail2ban_ignores_panel' => true, 'fail2ban_recidive_reads_log' => true, 'fail2ban_sshd_counts_hour' => true, 'fail2ban_bans_permanently' => true]);
    }

    /**
     * The probes jail reads every site's access log. Cloudflare's addresses are never banned, since nginx logs them for
     * requests it can't take a visitor's address from, and banning one would cut off every visitor routed through it.
     */
    protected function probesJail(): string
    {
        $maxRetry = (int) config('security-scanner.fail2ban_probes');
        $ignore = self::probesIgnoreList($this->server);
        $jail = self::PROBES_JAIL;

        return implode("\n", [
            "[{$jail}]",
            'enabled = true',
            'port = http,https',
            "filter = {$jail}",
            'logpath = /var/log/nginx/*access.log',
            'backend = auto',
            'findtime = 1d',
            "maxretry = {$maxRetry}",
            'bantime = -1',
            "ignoreip = {$ignore}",
            '# Ban in nginx as well as the firewall, which never sees visitors to sites proxied by Cloudflare.',
            'action = %(action_)s',
            '         '.self::NGINX_ACTION,
            '',
            '[recidive]',
            'action = %(action_)s',
            '         '.self::NGINX_ACTION,
        ]);
    }

    /**
     * The addresses the jails never ban: the server itself, Swage, and the addresses trusted on the server.
     */
    public static function ignoreList(Server $server): string
    {
        $known = ScannerState::for($server)->panel_address;

        return implode(' ', array_unique(array_filter([
            '127.0.0.1/8',
            '::1',
            self::PANEL_ADDRESS,
            filter_var($known, FILTER_VALIDATE_IP) ? $known : null,
            ...TrustedAddress::rangesFor($server->id),
        ])));
    }

    /**
     * The addresses the probes jail never bans, which sets its own list to add Cloudflare's.
     */
    public static function probesIgnoreList(Server $server): string
    {
        return implode(' ', [self::ignoreList($server), ...CloudflareAddresses::ranges()]);
    }

    /**
     * Deny a banned address in /etc/nginx/conf.d/swage-fail2ban-<jail>.conf, which every site inherits, and reload
     * nginx when its config is valid. fail2ban restores its bans on start, so stopping it empties the file.
     */
    protected function nginxAction(): string
    {
        $reload = 'nginx -t -q && systemctl reload nginx';

        return implode("\n", [
            '[Definition]',
            'actionstart = touch <file>',
            "actionstop = : > <file>\n             {$reload}",
            "actionban = grep -qxF 'deny <ip>;' <file> || echo 'deny <ip>;' >> <file>\n            {$reload}",
            "actionunban = grep -vxF 'deny <ip>;' <file> > <file>.tmp; mv <file>.tmp <file>\n              {$reload}",
            '',
            '[Init]',
            'file = /etc/nginx/conf.d/swage-fail2ban-<name>.conf',
        ]);
    }

    /**
     * The probes filter takes the path from each request in nginx's combined format, up to its response status, then
     * matches it against the scanner's probe patterns. Patterns only counted when a request fails also need the status
     * to be 403 or 404. fail2ban removes the date from a line before matching it, leaving empty brackets.
     */
    protected function probesFilter(): string
    {
        $patterns = collect(config('security-scanner.probes'))
            ->map(fn (string $pattern): string => $this->fail2banRegex($pattern))
            ->merge(collect(config('security-scanner.probes_when_failed'))
                ->map(fn (string $pattern): string => $this->fail2banRegex($pattern).'[^"]*" 40[34]$'))
            ->implode("\n            ");

        return implode("\n", [
            '[Definition]',
            'prefregex = ^<HOST> \S+ \S+ \[\] "[A-Z]+ <F-CONTENT>[^ "]+[^"]*" \d{3}</F-CONTENT>',
            "failregex = {$patterns}",
        ]);
    }

    /**
     * Turn one of the scanner's PHP patterns into a regex for fail2ban's config, which treats % as special.
     */
    protected function fail2banRegex(string $pattern): string
    {
        preg_match('/^(.)(.*)\1([a-z]*)$/s', $pattern, $parts);
        $regex = str_replace('%', '%%', $parts[2]);

        return str_contains($parts[3], 'i') ? "(?i:{$regex})" : $regex;
    }
}
