<?php

namespace Swage\SecurityScanner\Console;

use App\Enums\ServerStatus;
use Illuminate\Console\Command;
use Swage\SecurityScanner\Jobs\ScanServerLogs;
use Swage\SecurityScanner\Models\ScannerState;

class ScanCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security-scanner:scan';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Scan the logs of every server the security scanner is turned on for';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $states = ScannerState::query()
            ->where('enabled', true)
            ->whereHas('server', fn ($query) => $query->where('status', ServerStatus::Active))
            ->with('server')
            ->get();

        $states->each(fn (ScannerState $state) => ScanServerLogs::dispatch($state));

        $this->components->info("Scanning {$states->count()} server(s).");

        return self::SUCCESS;
    }
}
