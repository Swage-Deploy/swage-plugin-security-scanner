<?php

namespace Swage\SecurityScanner\Jobs;

use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Scanning\LogScanner;
use Throwable;

/**
 * Scans a server's logs. Scans are not recorded in the server's activity log, since they run every few minutes
 * without changing anything.
 */
class ScanServerLogs implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $timeout = 90;

    public int $tries = 1;

    public function __construct(public ScannerState $state) {}

    /**
     * Only one scan of a server may be queued at a time, so a slow server never builds up a queue of them.
     */
    public function uniqueId(): string
    {
        return (string) $this->state->server_id;
    }

    /**
     * Execute the job. A server that cannot be read keeps its cursors, so the next scan picks up where this one
     * would have.
     */
    public function handle(LogScanner $scanner): void
    {
        if (! $this->state->enabled) {
            return;
        }

        try {
            $scanner->scan($this->state);
        } catch (Throwable $exception) {
            $this->state->update(['last_error' => $this->state->server->redactSecrets($exception->getMessage())]);
        }
    }
}
