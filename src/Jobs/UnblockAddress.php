<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Enums\ResourceStatus;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\Models\BlockedAddress;
use Throwable;

class UnblockAddress implements ShouldQueue
{
    use Queueable;

    public int $timeout = 60;

    public int $tries = 1;

    public function __construct(public BlockedAddress $address) {}

    /**
     * Execute the job. An address whose rule was already removed by hand is unblocked all the same.
     */
    public function handle(RunServerTask $runTask): void
    {
        $ip = escapeshellarg($this->address->ip);
        $deny = escapeshellarg("deny {$this->address->ip};");
        $list = BlockedAddress::NGINX_DENY_PATH;
        $lock = BlockedAddress::LOCK_PATH;

        $runTask->run($this->address->server, "Unblocking {$this->address->ip} in the firewall and nginx", <<<BASH
        set -Eeuo pipefail

        ufw delete deny from {$ip} || echo "No firewall rule was blocking {$this->address->ip}."

        if [ -f {$list} ]; then
            exec 9> {$lock}
            flock 9
            grep -vxF -- {$deny} {$list} > {$list}.tmp || true
            mv {$list}.tmp {$list}
            nginx -t -q
            systemctl reload nginx
        fi
        BASH, timeout: 60);

        $this->address->delete();
    }

    /**
     * Handle a job failure.
     */
    public function failed(?Throwable $exception): void
    {
        $this->address->update(['status' => ResourceStatus::Failed]);
    }
}
