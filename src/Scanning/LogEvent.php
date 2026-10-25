<?php

namespace Swage\SecurityScanner\Scanning;

use Carbon\CarbonImmutable;
use Swage\SecurityScanner\Enums\EventKind;

/**
 * One line of a log that is worth counting.
 */
final readonly class LogEvent
{
    /**
     * @param  string  $source  The log the line came from: "ssh", "sudo", "nginx", or a site's domain.
     * @param  string|null  $target  The username or path involved, when there is one.
     */
    public function __construct(
        public EventKind $kind,
        public CarbonImmutable $occurredAt,
        public ?string $ip,
        public string $source,
        public ?string $target = null,
    ) {}
}
