<?php

namespace Swage\SecurityScanner\Models;

use App\Models\Server;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * An address fail2ban had banned on a server at the last scan, in any jail. Bans are permanent, so a server can have
 * many of them: they are kept as rows, rather than one list, so the panel can page through them and leave them out of
 * other lists in the database.
 */
#[Table('security_scanner_fail2ban_bans')]
#[Fillable(['server_id', 'ip'])]
class Fail2banBan extends Model
{
    /**
     * Make a server's bans match what fail2ban reported, keeping when each address was first seen banned.
     *
     * @param  list<string>  $ips
     */
    public static function sync(int $serverId, array $ips): void
    {
        $have = array_flip(static::query()->where('server_id', $serverId)->pluck('ip')->all());
        $want = array_flip($ips);

        foreach (array_chunk(array_keys(array_diff_key($have, $want)), 500) as $gone) {
            static::query()->where('server_id', $serverId)->whereIn('ip', $gone)->delete();
        }

        $now = now();

        foreach (array_chunk(array_keys(array_diff_key($want, $have)), 500) as $new) {
            static::query()->insert(array_map(fn (string $ip): array => ['server_id' => $serverId, 'ip' => $ip, 'created_at' => $now, 'updated_at' => $now], $new));
        }
    }

    /**
     * @return BelongsTo<Server, $this>
     */
    public function server(): BelongsTo
    {
        return $this->belongsTo(Server::class);
    }
}
