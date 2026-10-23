<?php

namespace Swage\SecurityScanner\Models;

use App\Enums\ResourceStatus;
use App\Models\Server;
use App\Models\User;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * An address the server's firewall denies everything from, added from the security scanner's panel.
 */
#[Table('security_scanner_blocked_addresses')]
#[Fillable(['server_id', 'ip', 'reason', 'status', 'blocked_by_id'])]
class BlockedAddress extends Model
{
    /**
     * The comment Swage gives the firewall rules it adds, so they can be told apart from others.
     */
    public const string RULE_COMMENT = 'Blocked by Swage security scanner';

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => ResourceStatus::class,
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
    public function blockedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'blocked_by_id');
    }
}
