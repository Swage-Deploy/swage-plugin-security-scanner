<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Models\Server;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\Models\ScannerState;

/**
 * Installs fail2ban to ban addresses that keep failing to log in over SSH, with the same jails as the Swage host:
 * an hour's ban after five failures in ten minutes, and a week's ban for addresses banned three times in a day.
 */
class InstallFail2ban implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

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

        $runTask->run($this->server, 'Installing fail2ban', <<<BASH
        set -Eeuo pipefail

        export DEBIAN_FRONTEND=noninteractive

        apt-get update -q
        apt-get install -yq -o DPkg::Lock::Timeout=300 fail2ban

        cat > /etc/fail2ban/jail.d/swage.conf <<'CONF'
        [DEFAULT]
        bantime = 1h
        findtime = 10m
        maxretry = 5
        backend = systemd

        [sshd]
        enabled = true
        port = {$port}

        [recidive]
        enabled = true
        bantime = 1w
        findtime = 1d
        maxretry = 3
        CONF

        systemctl enable fail2ban
        systemctl restart fail2ban

        echo "fail2ban is installed."
        BASH);

        ScannerState::for($this->server)->update(['fail2ban_installed' => true]);
    }
}
