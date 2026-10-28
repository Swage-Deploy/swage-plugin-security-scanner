<?php

namespace Swage\SecurityScanner;

use App\Plugins\HasPluginSettings;
use App\SourceControl\Setting;

/**
 * The integration with the settings of its AI review. Plugin settings need Swage v1.3.0, so on older versions the
 * plugin registers SecurityScannerIntegration instead, without them.
 */
class ConfigurableSecurityScannerIntegration extends SecurityScannerIntegration implements HasPluginSettings
{
    public function settings(): array
    {
        return [
            new Setting('url', __('API URL'), __('The base URL of an OpenAI compatible API, ending before /chat/completions.'), Setting::URL, placeholder: 'https://api.openai.com/v1'),
            new Setting('api_key', __('API key'), __('Sent as a bearer token. Leave it blank for APIs that don\'t need one, such as a local Ollama.'), Setting::SECRET, required: false),
            new Setting('model', __('Model'), __('The model that reviews servers. It must support structured output (JSON schema responses).'), placeholder: 'gpt-4.1'),
        ];
    }

    public function settingsDescription(): string
    {
        return __('The AI review sends what the scanner recorded about a server, and a read-only snapshot of how it is set up, to this API, and shows the findings and suggestions it sends back. It never changes a server: nothing it suggests is run. Turn it on per server from the server\'s Security scanner tab.');
    }
}
