<?php

namespace Swage\SecurityScanner;

use App\Models\Server;
use App\Servers\ServerIntegration;

class SecurityScannerIntegration implements ServerIntegration
{
    public function id(): string
    {
        return 'security-scanner';
    }

    public function settingsComponent(): string
    {
        return 'security-scanner.panel';
    }

    /**
     * The scanner stores no secrets of its own.
     */
    public function secrets(Server $server): array
    {
        return [];
    }
}
