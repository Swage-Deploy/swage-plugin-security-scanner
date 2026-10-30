<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Models\Server;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\TrustedAddress;

/**
 * Brings fail2ban's list of addresses it never bans up to date with the addresses trusted on the server, and lifts
 * its bans on them. It only rewrites that list and reloads fail2ban, which keeps its bans and the failures it has
 * counted, rather than installing it again.
 */
class UpdateFail2banTrustedAddresses implements ShouldQueue
{
    use Queueable;

    public int $timeout = 120;

    public int $tries = 1;

    public function __construct(public Server $server) {}

    /**
     * Execute the job.
     */
    public function handle(RunServerTask $runTask): void
    {
        $state = ScannerState::for($this->server);

        if (! $state->fail2ban_installed) {
            return;
        }

        $ranges = TrustedAddress::rangesFor($this->server->id);
        $ignore = InstallFail2ban::ignoreList($this->server);
        $probesIgnore = InstallFail2ban::probesIgnoreList($this->server);
        $panelAddress = InstallFail2ban::PANEL_ADDRESS;
        $jail = InstallFail2ban::PROBES_JAIL;
        $unban = implode(' ', array_map('escapeshellarg', array_values(array_filter(
            $state->fail2ban_banned ?? [],
            fn (string $ip): bool => TrustedAddress::covers($ranges, $ip),
        ))));

        // Addresses are checked when they are trusted, so the lists hold nothing but addresses, ranges and spaces.
        $runTask->run($this->server, 'Updating the addresses fail2ban never bans', <<<BASH
        set -Eeuo pipefail

        panel_address=\${SSH_CLIENT%% *}
        [[ "\$panel_address" =~ ^[0-9A-Fa-f:.]+$ ]] || panel_address=''

        sed -i "s|^ignoreip = .*|ignoreip = {$ignore}|; s/{$panelAddress}/\$panel_address/" /etc/fail2ban/jail.d/swage.conf

        if [ -f /etc/fail2ban/jail.d/{$jail}.conf ]; then
            sed -i "s|^ignoreip = .*|ignoreip = {$probesIgnore}|; s/{$panelAddress}/\$panel_address/" /etc/fail2ban/jail.d/{$jail}.conf
        fi

        fail2ban-client reload

        unban=({$unban})
        if [ \${#unban[@]} -gt 0 ]; then
            fail2ban-client unban "\${unban[@]}" || true
        fi

        echo "fail2ban's trusted addresses are up to date."
        BASH, timeout: 120);
    }
}
