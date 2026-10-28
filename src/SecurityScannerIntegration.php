<?php

namespace Swage\SecurityScanner;

use App\Models\Server;
use App\Plugins\HasPluginTab;
use App\Servers\ServerIntegration;
use Swage\SecurityScanner\Ai\AiSettings;

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
     * The AI review's API key is the only secret the scanner stores. It is never sent to servers.
     */
    public function secrets(Server $server): array
    {
        return array_values(array_filter([app(AiSettings::class)->apiKey()]));
    }
}
