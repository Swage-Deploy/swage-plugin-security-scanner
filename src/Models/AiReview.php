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
use Swage\SecurityScanner\Enums\AlertSeverity;

/**
 * What an AI model made of a server's security: a summary and findings, each with a suggestion for a person to act
 * on. Reviews are only ever read: nothing in them is run.
 *
 * @property list<array{severity: string, title: string, detail: string, suggestion: string}> $findings
 */
#[Table('security_scanner_ai_reviews')]
#[Fillable(['server_id', 'model', 'summary', 'findings', 'requested_by_id'])]
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
     * The findings, most severe first.
     *
     * @return list<array{severity: AlertSeverity, title: string, detail: string, suggestion: string}>
     */
    public function sortedFindings(): array
    {
        return collect($this->findings)
            ->map(fn (array $finding): array => [...$finding, 'severity' => AlertSeverity::tryFrom($finding['severity']) ?? AlertSeverity::Low])
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
