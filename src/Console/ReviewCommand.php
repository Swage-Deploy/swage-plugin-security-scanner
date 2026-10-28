<?php

namespace Swage\SecurityScanner\Console;

use App\Enums\ServerStatus;
use Illuminate\Console\Command;
use Swage\SecurityScanner\Ai\AiSettings;
use Swage\SecurityScanner\Jobs\ReviewServerSecurity;
use Swage\SecurityScanner\Models\ScannerState;

class ReviewCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security-scanner:review';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Ask the AI model to review the servers it is turned on for that are due a review';

    /**
     * Execute the console command.
     */
    public function handle(AiSettings $settings): int
    {
        if (! $settings->isConfigured()) {
            $this->components->info('The AI review is not configured.');

            return self::SUCCESS;
        }

        $due = now()->subHours(max(1, (int) config('security-scanner.ai.interval_hours')));

        $states = ScannerState::query()
            ->where('ai_enabled', true)
            ->where(fn ($query) => $query->whereNull('ai_reviewed_at')->orWhere('ai_reviewed_at', '<=', $due))
            ->whereHas('server', fn ($query) => $query->where('status', ServerStatus::Active))
            ->with('server')
            ->get();

        $states->each(fn (ScannerState $state) => ReviewServerSecurity::dispatch($state));

        $this->components->info("Reviewing {$states->count()} server(s).");

        return self::SUCCESS;
    }
}
