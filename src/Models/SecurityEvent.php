<?php

namespace Swage\SecurityScanner\Models;

use App\Models\Server;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Swage\SecurityScanner\Enums\EventKind;

/**
 * How many times a kind of event happened from one address, to one log source, within one hour. The targets are the
 * first few distinct usernames or paths involved.
 */
#[Table('security_scanner_events')]
#[Fillable(['server_id', 'kind', 'ip', 'source', 'bucket', 'count', 'targets', 'first_seen_at', 'last_seen_at'])]
class SecurityEvent extends Model
{
    use MassPrunable;

    /**
     * The most distinct targets kept on each row.
     */
    public const int MAX_TARGETS = 20;

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'kind' => EventKind::class,
            'bucket' => 'datetime',
            'count' => 'integer',
            'targets' => 'array',
            'first_seen_at' => 'datetime',
            'last_seen_at' => 'datetime',
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
     * @return Builder<SecurityEvent>
     */
    public function prunable(): Builder
    {
        return static::where('bucket', '<', now()->subDays(config('security-scanner.retention_days')));
    }
}
