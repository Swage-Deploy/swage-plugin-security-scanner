<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Models\Server;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\CloudflareAddresses;
use Swage\SecurityScanner\Models\ScannerState;

/**
 * Installs fail2ban to ban addresses that keep failing to log in over SSH, with the same jails as the Swage host:
 * an hour's ban after five failures in ten minutes, and a week's ban for addresses banned three times in a day.
 *
 * On servers with nginx it also bans addresses probing for vulnerable files from the sites for an hour, using the
 * scanner's own probe patterns, and they count towards the week's ban too. Bans from the probes and recidive jails
 * are also denied in nginx, which takes the visitor's address from Cloudflare, so visitors to sites proxied by
 * Cloudflare are banned too. Running it again updates the jails.
 *
 * Swage's own address is never banned, since that would lock Swage out of the server. It is taken from the SSH
 * connection the install runs over, as well as the address the scanner last saw Swage connect from.
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
        $ignore = $this->ignored();

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

        [sshd]
        enabled = true
        port = {$port}

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

        ScannerState::for($this->server)->update(['fail2ban_installed' => true, 'fail2ban_ignores_panel' => true, 'fail2ban_recidive_reads_log' => true]);
    }

    /**
     * The probes jail reads every site's access log. Cloudflare's addresses are never banned, since nginx logs them for
     * requests it can't take a visitor's address from, and banning one would cut off every visitor routed through it.
     */
    protected function probesJail(): string
    {
        $maxRetry = (int) config('security-scanner.fail2ban_probes');
        $ignore = $this->ignored(CloudflareAddresses::ranges());
        $jail = self::PROBES_JAIL;

        return implode("\n", [
            "[{$jail}]",
            'enabled = true',
            'port = http,https',
            "filter = {$jail}",
            'logpath = /var/log/nginx/*access.log',
            'backend = auto',
            'findtime = 1h',
            "maxretry = {$maxRetry}",
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
     * The addresses a jail never bans: the server itself, Swage, and any others given.
     *
     * @param  list<string>  $others
     */
    protected function ignored(array $others = []): string
    {
        $known = ScannerState::for($this->server)->panel_address;

        return implode(' ', array_filter([
            '127.0.0.1/8',
            '::1',
            self::PANEL_ADDRESS,
            filter_var($known, FILTER_VALIDATE_IP) ? $known : null,
            ...$others,
        ]));
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
     * The probes filter takes the path from each request in nginx's combined format, then matches it against the
     * scanner's probe patterns. fail2ban removes the date from a line before matching it, leaving empty brackets.
     */
    protected function probesFilter(): string
    {
        $patterns = collect(config('security-scanner.probes'))
            ->map(function (string $pattern): string {
                preg_match('/^(.)(.*)\1([a-z]*)$/s', $pattern, $parts);
                $regex = str_replace('%', '%%', $parts[2]);

                return str_contains($parts[3], 'i') ? "(?i:{$regex})" : $regex;
            })
            ->implode("\n            ");

        return implode("\n", [
            '[Definition]',
            'prefregex = ^<HOST> \S+ \S+ \[\] "[A-Z]+ <F-CONTENT>[^ "]+</F-CONTENT>',
            "failregex = {$patterns}",
        ]);
    }
}
