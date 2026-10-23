<?php

namespace Swage\SecurityScanner\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Swage\SecurityScanner\Models\SecurityAlert;

/**
 * A new alert was opened. Further occurrences counted on an open alert do not dispatch it again, so listeners, such
 * as notifications or analysis, run once per alert.
 */
class AlertRaised
{
    use Dispatchable, SerializesModels;

    public function __construct(public SecurityAlert $alert) {}
}
