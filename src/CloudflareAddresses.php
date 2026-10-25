<?php

namespace Swage\SecurityScanner;

use App\Sites\CloudflareNetworks;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Cloudflare's proxy connects to sites from these ranges. Sites log the visitor behind it, but requests nginx cannot
 * take a visitor from, such as ones for a hostname no site serves, are logged as Cloudflare's address. Blocking one
 * would cut off every visitor Cloudflare routes through it, so they are never counted or blocked.
 */
final class CloudflareAddresses
{
    public static function contains(string $ip): bool
    {
        return IpUtils::checkIp($ip, self::ranges());
    }

    /**
     * Swage's own list of the ranges, which it updates as Cloudflare adds ranges.
     *
     * @return list<string>
     */
    public static function ranges(): array
    {
        return CloudflareNetworks::RANGES;
    }
}
