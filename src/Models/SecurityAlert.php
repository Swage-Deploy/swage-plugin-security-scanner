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
use Swage\SecurityScanner\Enums\AlertRule;
use Swage\SecurityScanner\Enums\AlertSeverity;

/**
 * Something in a server's logs that someone should look at. An alert stays open until it is resolved, and further
 * occurrences from the same subject are counted on it.
 *
 * @property array<string, mixed>|null $details
 */
#[Table('security_scanner_alerts')]
#[Fillable(['server_id', 'rule', 'severity', 'subject', 'details', 'occurrences', 'first_seen_at', 'last_seen_at', 'resolved_at', 'resolved_by_id'])]
class SecurityAlert extends Model
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
            'rule' => AlertRule::class,
            'severity' => AlertSeverity::class,
            'details' => 'array',
            'occurrences' => 'integer',
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
            'resolved_at' => 'datetime',
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
    public function resolvedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'resolved_by_id');
    }

    /**
     * @param  Builder<SecurityAlert>  $query
     */
    public function scopeOpen(Builder $query): void
    {
        $query->whereNull('resolved_at');
    }

    public function isOpen(): bool
    {
        return $this->resolved_at === null;
    }

    /**
     * Describe what was seen, in a sentence.
     */
    public function summary(): string
    {
        $details = $this->details ?? [];
        $list = fn (string $key): string => implode(', ', array_slice($details[$key] ?? [], 0, 3));

        return match ($this->rule) {
            AlertRule::SshBruteForce => __(':count attempts in the last hour, as :users.', ['count' => $details['count'] ?? 0, 'users' => $list('targets')]),
            AlertRule::SshLoginAfterFailures => __('Logged in as :user after :failed failed attempts from the same address.', ['user' => $details['user'] ?? '?', 'failed' => $details['failed_attempts'] ?? 0]),
            AlertRule::SshLoginNewAddress => __('Logged in as :user.', ['user' => $details['user'] ?? '?']),
            AlertRule::SudoFailure => trans_choice(':user failed to use sudo once.|:user failed to use sudo :count times.', $this->occurrences, ['user' => $this->subject]),
            AlertRule::HttpProbing => __(':count requests in the last hour on :sites, such as :paths', ['count' => $details['count'] ?? 0, 'sites' => $list('sources'), 'paths' => $list('targets')]),
            AlertRule::HttpLoginBruteForce => __(':count login submissions in the last hour on :sites.', ['count' => $details['count'] ?? 0, 'sites' => $list('sources')]),
        };
    }

    public function resolve(?User $user = null): void
    {
        $this->update(['resolved_at' => now(), 'resolved_by_id' => $user?->id]);
    }

    /**
     * @return Builder<SecurityAlert>
     */
    public function prunable(): Builder
    {
        return static::where('resolved_at', '<', now()->subDays(90));
    }
}
