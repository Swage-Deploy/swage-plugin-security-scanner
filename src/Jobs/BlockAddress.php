<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Enums\ResourceStatus;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\Models\BlockedAddress;
use Throwable;

/**
 * Denies everything from an address in the server's firewall. The rule is put first, ahead of the rules that allow
 * SSH and HTTP.
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
        $comment = escapeshellarg(BlockedAddress::RULE_COMMENT);

        $runTask->run($this->address->server, "Blocking {$this->address->ip} in the firewall", <<<BASH
        set -Eeuo pipefail
        ufw prepend deny from {$ip} comment {$comment}
        BASH, timeout: 30);

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
