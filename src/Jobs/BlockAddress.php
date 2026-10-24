<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Enums\ResourceStatus;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\Models\BlockedAddress;
use Throwable;

/**
 * Denies everything from an address in the server's firewall, putting the rule ahead of the ones that allow SSH and
 * HTTP, and adds it to the list nginx denies, so it is blocked from sites behind Cloudflare too. Running it for an
 * address that is already blocked changes nothing, so scans use it to restore an address missing from the list.
 */
class BlockAddress implements ShouldQueue
{
    use Queueable;

    public int $timeout = 60;

    public int $tries = 1;

    public function __construct(public BlockedAddress $address) {}

    /**
     * Execute the job.
     */
    public function handle(RunServerTask $runTask): void
    {
        $this->address->update(['status' => ResourceStatus::Installing]);

        $ip = escapeshellarg($this->address->ip);
        $deny = escapeshellarg("deny {$this->address->ip};");
        $comment = escapeshellarg(BlockedAddress::RULE_COMMENT);
        $list = BlockedAddress::NGINX_DENY_PATH;
        $lock = BlockedAddress::LOCK_PATH;

        $runTask->run($this->address->server, "Blocking {$this->address->ip} in the firewall and nginx", <<<BASH
        set -Eeuo pipefail

        ufw prepend deny from {$ip} comment {$comment}

        if command -v nginx > /dev/null 2>&1; then
            exec 9> {$lock}
            flock 9
            touch {$list}
            grep -qxF -- {$deny} {$list} || echo {$deny} >> {$list}
            nginx -t -q
            systemctl reload nginx
        fi
        BASH, timeout: 60);

        $this->address->update(['status' => ResourceStatus::Installed]);
    }

    /**
     * Handle a job failure.
     */
    public function failed(?Throwable $exception): void
    {
        $this->address->update(['status' => ResourceStatus::Failed]);
    }
}
