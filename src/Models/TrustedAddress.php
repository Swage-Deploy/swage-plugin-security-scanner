<?php

namespace Swage\SecurityScanner\Models;

use App\Models\Server;
use App\Models\User;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * An address, or a range such as 203.0.113.0/24, people trust on a server, such as an office's. The scanner never
 * counts or alerts on it, it can't be blocked, fail2ban never bans it, and the AI review leaves it out.
 */
#[Table('security_scanner_trusted_addresses')]
#[Fillable(['server_id', 'ip', 'note', 'trusted_by_id'])]
class TrustedAddress extends Model
{
    /**
     * The widest ranges that can be trusted, so a typo can't exempt a large part of the internet.
     */
    public const int MIN_IPV4_PREFIX = 16;

    public const int MIN_IPV6_PREFIX = 32;

    /**
     * The addresses and ranges trusted on a server.
     *
     * @return list<string>
     */
    public static function rangesFor(int $serverId): array
    {
        return static::query()->where('server_id', $serverId)->orderBy('ip')->pluck('ip')->all();
    }

    /**
     * Determine if an address is in one of the given ranges.
     *
     * @param  list<string>  $ranges
     */
    public static function covers(array $ranges, ?string $ip): bool
    {
        return $ip !== null && $ranges !== [] && IpUtils::checkIp($ip, $ranges);
    }

    /**
     * An address or range in its plain form, such as 2001:db8::/48, or null when it isn't one or is too wide.
     */
    public static function normalize(string $value): ?string
    {
        [$ip, $prefix] = array_pad(explode('/', trim($value), 2), 2, null);

        if (! filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }

        $ip = (string) inet_ntop((string) inet_pton($ip));
        $max = str_contains($ip, ':') ? 128 : 32;

        if ($prefix === null) {
            return $ip;
        }

        if (! ctype_digit($prefix) || (int) $prefix > $max || (int) $prefix < ($max === 32 ? self::MIN_IPV4_PREFIX : self::MIN_IPV6_PREFIX)) {
            return null;
        }

        if ((int) $prefix === $max) {
            return $ip;
        }

        // Clear the host bits, so 203.0.113.7/24 is stored, shown and given to fail2ban as 203.0.113.0/24.
        $bytes = inet_pton($ip);
        $network = '';

        foreach (str_split($bytes) as $index => $byte) {
            $keep = max(0, min(8, (int) $prefix - $index * 8));
            $network .= chr(ord($byte) & (0xFF << (8 - $keep)) & 0xFF);
        }

        return inet_ntop($network).'/'.(int) $prefix;
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
    public function trustedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'trusted_by_id');
    }
}
