<?php

namespace Swage\SecurityScanner;

use App\Models\Server;
use App\Plugins\HasPluginTab;
use App\Servers\ServerIntegration;

class SecurityScannerIntegration implements HasPluginTab, ServerIntegration
{
    public function id(): string
    {
        return 'security-scanner';
    }

    public function settingsComponent(): string
    {
        return 'security-scanner.panel';
    }

    public function tabLabel(): string
    {
        return __('Security scanner');
    }

    public function tabIcon(): string
    {
        return 'shield-check';
    }

    /**
     * The scanner stores no secrets.
     */
    public function secrets(Server $server): array
    {
        return [];
    }
}
