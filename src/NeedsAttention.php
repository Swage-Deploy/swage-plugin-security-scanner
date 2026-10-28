<?php

namespace Swage\SecurityScanner;

use App\Enums\ResourceStatus;
use App\Models\Server;
use Illuminate\Database\Eloquent\Collection;
use Swage\SecurityScanner\Enums\AlertSeverity;
use Swage\SecurityScanner\Models\AiReview;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\IgnoredFinding;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityAlert;

/**
 * What the security panel has for people to look at on each server: the open alerts it lists, and the latest AI
 * review's findings nobody has ignored. Servers are read together, in the same few queries however many there are.
 */
class NeedsAttention
{
    /**
     * @param  Collection<int, Server>  $servers
     * @return array<int, array{alerts: int, findings: int, severity: AlertSeverity}> By server id. Servers with nothing to look at are left out.
     */
    public function for(Collection $servers): array
    {
        $ids = $servers->modelKeys();

        if ($ids === []) {
            return [];
        }

        $states = ScannerState::query()->whereIn('server_id', $ids)->get(['server_id', 'fail2ban_banned', 'ai_enabled'])->keyBy('server_id');
        $blocked = BlockedAddress::query()->whereIn('server_id', $ids)->where('status', ResourceStatus::Installed)->get(['server_id', 'ip'])->groupBy('server_id');
        $items = [];

        // The alerts the panel lists: open ones, leaving out addresses fail2ban has banned or that are blocked.
        SecurityAlert::query()->whereIn('server_id', $ids)->open()->get(['server_id', 'subject', 'severity'])
            ->groupBy('server_id')
            ->each(function (Collection $alerts, int $serverId) use ($states, $blocked, &$items): void {
                $banned = [...$states->get($serverId)?->fail2ban_banned ?? [], ...$blocked->get($serverId)?->pluck('ip') ?? []];

                foreach ($alerts->reject(fn (SecurityAlert $alert): bool => in_array($alert->subject, $banned, true)) as $alert) {
                    $this->add($items, $serverId, 'alerts', $alert->severity);
                }
            });

        // The latest review's findings, on servers still reviewed, leaving out the ones people have ignored.
        $reviewed = $states->filter(fn (ScannerState $state): bool => $state->ai_enabled)->keys()->all();

        if ($reviewed !== []) {
            $ignored = IgnoredFinding::query()->whereIn('server_id', $reviewed)->get(['server_id', 'key'])->groupBy('server_id');

            AiReview::query()
                ->whereIn('id', AiReview::query()->selectRaw('max(id)')->whereIn('server_id', $reviewed)->groupBy('server_id'))
                ->get(['id', 'server_id', 'findings'])
                ->each(function (AiReview $review) use ($ignored, &$items): void {
                    $keys = $ignored->get($review->server_id)?->pluck('key')->all() ?? [];

                    foreach ($review->sortedFindings() as $finding) {
                        if (! in_array($finding['key'], $keys, true)) {
                            $this->add($items, $review->server_id, 'findings', $finding['severity']);
                        }
                    }
                });
        }

        return $items;
    }

    /**
     * @param  array<int, array{alerts: int, findings: int, severity: AlertSeverity}>  $items
     */
    protected function add(array &$items, int $serverId, string $kind, AlertSeverity $severity): void
    {
        $items[$serverId] ??= ['alerts' => 0, 'findings' => 0, 'severity' => $severity];
        $items[$serverId][$kind]++;

        if ($severity->rank() > $items[$serverId]['severity']->rank()) {
            $items[$serverId]['severity'] = $severity;
        }
    }
}
