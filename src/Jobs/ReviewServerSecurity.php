<?php

namespace Swage\SecurityScanner\Jobs;

use App\Models\User;
use App\Ssh\RemoteShell;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use RuntimeException;
use Swage\SecurityScanner\Ai\AiSettings;
use Swage\SecurityScanner\Ai\PostureScript;
use Swage\SecurityScanner\Ai\ReviewContext;
use Swage\SecurityScanner\Ai\SecurityReviewer;
use Swage\SecurityScanner\Enums\AlertSeverity;
use Swage\SecurityScanner\Models\AiReview;
use Swage\SecurityScanner\Models\ScannerState;
use Throwable;

/**
 * Asks the AI model to review a server's security. The only thing it runs on the server is the read-only snapshot
 * script, which the AI has no say in, and the only thing it writes is the review, to Swage's database. Reviews are
 * not recorded in the server's activity log, since they change nothing.
 */
class ReviewServerSecurity implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $timeout;

    public int $tries = 1;

    public function __construct(public ScannerState $state, public ?User $requestedBy = null)
    {
        // Long enough to read the server and wait for the API.
        $this->timeout = (int) config('security-scanner.ai.timeout') + 90;
    }

    /**
     * Only one review of a server may be queued at a time.
     */
    public function uniqueId(): string
    {
        return (string) $this->state->server_id;
    }

    /**
     * Execute the job. A review that fails still counts as the server's latest, so a broken API isn't asked again
     * until the next review is due.
     */
    public function handle(RemoteShell $shell, AiSettings $settings, ReviewContext $context): void
    {
        if (! $this->state->ai_enabled || ! $settings->isConfigured()) {
            return;
        }

        try {
            $snapshot = $this->snapshot($shell);
            $input = $context->encode($this->state, $snapshot);

            $response = (new SecurityReviewer)->prompt(
                ReviewContext::wrap($input),
                provider: $settings->provider(),
                model: $settings->model(),
                timeout: (int) config('security-scanner.ai.timeout'),
            );

            AiReview::create([
                'server_id' => $this->state->server_id,
                'model' => (string) $settings->model(),
                'reported_model' => $response->meta->model,
                'summary' => mb_strimwidth(trim((string) ($response['summary'] ?? '')), 0, 2000, '…'),
                'findings' => $this->findings($response['findings'] ?? []),
                'checked' => $this->checked($response['checked'] ?? []),
                'missing_sections' => PostureScript::missing($snapshot),
                'input' => $input,
                'input_tokens' => $response->usage->inputTokens ?: null,
                'output_tokens' => $response->usage->outputTokens ?: null,
                'requested_by_id' => $this->requestedBy?->id,
            ]);

            $this->state->update(['ai_reviewed_at' => now(), 'ai_error' => null]);
        } catch (Throwable $exception) {
            $message = $this->state->server->redactSecrets($exception->getMessage());

            if (filled($key = $settings->apiKey())) {
                $message = str_replace($key, '********', $message);
            }

            $this->state->update(['ai_reviewed_at' => now(), 'ai_error' => mb_strimwidth($message, 0, 1000, '…')]);
        }
    }

    /**
     * Read how the server is set up.
     *
     * @return array<string, string>
     *
     * @throws RuntimeException when the server cannot be read.
     */
    protected function snapshot(RemoteShell $shell): array
    {
        $script = PostureScript::make();
        $result = $shell->run($this->state->server, $script->render(), timeout: 60);

        if ($result->failed()) {
            throw new RuntimeException(trim("Reading the server's setup failed with exit code {$result->exitCode}. ".mb_strimwidth($result->output, 0, 500, '…')));
        }

        return $script->parse($result->output);
    }

    /**
     * Keep the entries of what the review checked that say what was seen, cut to a sensible length.
     *
     * @return list<array{area: string, observation: string}>
     */
    protected function checked(mixed $checked): array
    {
        return collect(is_array($checked) ? $checked : [])
            ->filter(fn (mixed $entry): bool => is_array($entry) && filled($entry['area'] ?? null) && filled($entry['observation'] ?? null))
            ->take(SecurityReviewer::MAX_CHECKED)
            ->map(fn (array $entry): array => [
                'area' => mb_strimwidth(trim((string) $entry['area']), 0, 120, '…'),
                'observation' => mb_strimwidth(trim((string) $entry['observation']), 0, 500, '…'),
            ])
            ->values()
            ->all();
    }

    /**
     * Keep the findings that have what the panel shows, cut to a sensible length.
     *
     * @return list<array{severity: string, title: string, detail: string, suggestion: string}>
     */
    protected function findings(mixed $findings): array
    {
        return collect(is_array($findings) ? $findings : [])
            ->filter(fn (mixed $finding): bool => is_array($finding) && filled($finding['title'] ?? null))
            ->take(SecurityReviewer::MAX_FINDINGS)
            ->map(fn (array $finding): array => [
                'severity' => (AlertSeverity::tryFrom((string) ($finding['severity'] ?? '')) ?? AlertSeverity::Low)->value,
                'title' => mb_strimwidth(trim((string) $finding['title']), 0, 200, '…'),
                'detail' => mb_strimwidth(trim((string) ($finding['detail'] ?? '')), 0, 2000, '…'),
                'suggestion' => mb_strimwidth(trim((string) ($finding['suggestion'] ?? '')), 0, 2000, '…'),
            ])
            ->values()
            ->all();
    }
}
