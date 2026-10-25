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
 * An address blocked from the security scanner's panel. The firewall denies its connections, which covers SSH and
 * sites reached directly, and nginx denies its requests, which covers sites proxied by Cloudflare: their connections
 * come from Cloudflare, but nginx takes the visitor's address from Cloudflare's header before it applies the list.
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
     * The list of addresses nginx denies. nginx includes conf.d at the http level, so every site inherits it.
     */
    public const string NGINX_DENY_PATH = '/etc/nginx/conf.d/swage-security-scanner-blocked.conf';

    /**
     * Held while the deny list is changed, so blocks and unblocks running at once never lose each other's change.
     */
    public const string LOCK_PATH = '/run/lock/swage-security-scanner.lock';

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
