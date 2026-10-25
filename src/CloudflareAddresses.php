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
    /**
     * Cloudflare's ranges, published at https://www.cloudflare.com/ips/, for Swage releases before v1.0.9, which do not
     * keep their own list.
     *
     * @var list<string>
     */
    public const array RANGES = [
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    public static function contains(string $ip): bool
    {
        return IpUtils::checkIp($ip, self::ranges());
    }

    /**
     * Swage's own list of the ranges when it keeps one, which it updates as Cloudflare adds ranges, or the plugin's.
     *
     * @return list<string>
     */
    public static function ranges(): array
    {
        return class_exists(CloudflareNetworks::class) ? CloudflareNetworks::RANGES : self::RANGES;
    }
}
