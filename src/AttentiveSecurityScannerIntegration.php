<?php

namespace Swage\SecurityScanner;

use App\Plugins\Attention;
use App\Plugins\HasAttention;
use Illuminate\Database\Eloquent\Collection;

/**
 * The integration, also saying which servers have open alerts or AI review findings, so Swage badges them on the
 * servers page and their Plugins tab. Badges need Swage v1.4.0, so on older versions the plugin registers one of the
 * integrations it extends instead.
 */
class AttentiveSecurityScannerIntegration extends ConfigurableSecurityScannerIntegration implements HasAttention
{
    public function attention(Collection $servers): array
    {
        return array_map(fn (array $item): Attention => new Attention(
            $item['alerts'] + $item['findings'],
            $item['severity']->value,
            $this->label($item['alerts'], $item['findings']),
        ), app(NeedsAttention::class)->for($servers));
    }

    protected function label(int $alerts, int $findings): string
    {
        $parts = array_filter([
            $alerts > 0 ? trans_choice(':count open SSH login alert|:count open SSH login alerts', $alerts) : null,
            $findings > 0 ? trans_choice(':count AI review finding|:count AI review findings', $findings) : null,
        ]);

        return __('Security scanner: :items', ['items' => implode(__(' and '), $parts)]);
    }
}
