<?php

namespace Swage\SecurityScanner;

use App\Plugins\Attention;
use App\Plugins\HasAttention;
use Illuminate\Database\Eloquent\Collection;

/**
 * The integration, also saying which servers have open alerts, so Swage badges them on the servers page and their
 * Plugins tab. Badges need Swage v1.3.3, so on older versions the plugin registers the integration it extends instead.
 */
class AttentiveSecurityScannerIntegration extends SecurityScannerIntegration implements HasAttention
{
    public function attention(Collection $servers): array
    {
        return array_map(fn (array $item): Attention => new Attention(
            $item['alerts'],
            $item['severity']->value,
            __('Security scanner: :items', ['items' => trans_choice(':count open SSH login alert|:count open SSH login alerts', $item['alerts'])]),
        ), app(NeedsAttention::class)->for($servers));
    }
}
