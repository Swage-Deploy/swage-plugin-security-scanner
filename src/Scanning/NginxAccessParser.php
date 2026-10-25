<?php

namespace Swage\SecurityScanner\Scanning;

use Carbon\CarbonImmutable;
use Swage\SecurityScanner\Enums\EventKind;
use Throwable;

/**
 * Reads nginx access logs in the combined format Swage's sites use. Ordinary requests are not counted: only probes
 * for vulnerable files, login form submissions, denied requests and requests for missing pages.
 *
 * Sites behind Cloudflare log the visitor's address, since Swage sets nginx's real IP from Cloudflare's networks.
 */
class NginxAccessParser
{
    /**
     * @return list<LogEvent>
     */
    public function parse(string $content, string $source): array
    {
        $events = [];

        foreach (explode("\n", $content) as $line) {
            if (! preg_match('/^(?<ip>\S+) \S+ \S+ \[(?<time>[^\]]+)\] "(?<request>(?:[^"\\\\]|\\\\.)*)" (?<status>\d{3}) /', $line, $matches)
                || ! filter_var($matches['ip'], FILTER_VALIDATE_IP)) {
                continue;
            }

            try {
                $time = CarbonImmutable::createFromFormat('d/M/Y:H:i:s O', $matches['time']);
            } catch (Throwable) {
                continue;
            }

            if (! $time) {
                continue;
            }

            [$method, $path] = array_pad(explode(' ', $matches['request'], 3), 2, '');
            $kind = $this->classify($method, $path, (int) $matches['status']);

            if ($kind) {
                $events[] = new LogEvent($kind, $time, $matches['ip'], $source, mb_strimwidth($path, 0, 200, '…'));
            }
        }

        return $events;
    }

    protected function classify(string $method, string $path, int $status): ?EventKind
    {
        foreach (config('security-scanner.probes') as $pattern) {
            if (preg_match($pattern, $path)) {
                return EventKind::HttpProbe;
            }
        }

        if ($method === 'POST' && preg_match('~/(login|signin|sign-in|auth/login)(\?|/|$)~i', $path)) {
            return EventKind::HttpLogin;
        }

        return match ($status) {
            401, 403 => EventKind::HttpDenied,
            404 => EventKind::HttpNotFound,
            default => null,
        };
    }
}
