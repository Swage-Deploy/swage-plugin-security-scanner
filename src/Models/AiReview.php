<?php

namespace Swage\SecurityScanner\Models;

use App\Models\Server;
use App\Models\User;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Swage\SecurityScanner\Ai\PostureScript;
use Swage\SecurityScanner\Enums\AlertSeverity;

/**
 * What an AI model made of a server's security: a summary and findings, each with a suggestion for a person to act
 * on. Reviews are only ever read: nothing in them is run.
 *
 * Each review keeps what it was sent, what the model says it checked and how many tokens it used, so people can
 * confirm that a review which found nothing really read the server.
 *
 * @property list<array{key?: string, severity: string, title: string, detail: string, suggestion: string}> $findings
 * @property list<array{area: string, observation: string}>|null $checked
 * @property list<string>|null $missing_sections
 */
#[Table('security_scanner_ai_reviews')]
#[Fillable(['server_id', 'model', 'reported_model', 'summary', 'findings', 'checked', 'missing_sections', 'input', 'input_tokens', 'output_tokens', 'requested_by_id'])]
class AiReview extends Model
{
    use MassPrunable;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'findings' => 'array',
            'checked' => 'array',
            'missing_sections' => 'array',
            'input_tokens' => 'integer',
            'output_tokens' => 'integer',
        ];
    }

    /**
     * @return BelongsTo<Server, $this>
     */
    public function server(): BelongsTo
    {
        return $this->belongsTo(Server::class);
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function requestedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'requested_by_id');
    }

    /**
     * What the snapshot could not read, by the names the review gives them.
     *
     * @return list<string>
     */
    public function missingLabels(): array
    {
        return array_values(array_map(fn (string $section): string => PostureScript::SECTIONS[$section] ?? $section, $this->missing_sections ?? []));
    }

    /**
     * The findings, most severe first, each with its key.
     *
     * @return list<array{key: string, severity: AlertSeverity, title: string, detail: string, suggestion: string}>
     */
    public function sortedFindings(): array
    {
        return collect($this->findings)
            ->map(fn (array $finding): array => [...$finding, 'key' => IgnoredFinding::keyFor($finding), 'severity' => AlertSeverity::tryFrom($finding['severity']) ?? AlertSeverity::Low])
            ->sortByDesc(fn (array $finding): int => $finding['severity']->rank())
            ->values()
            ->all();
    }

    /**
     * @return Builder<AiReview>
     */
    public function prunable(): Builder
    {
        return static::where('created_at', '<', now()->subDays(config('security-scanner.ai.retention_days')));
    }
}
