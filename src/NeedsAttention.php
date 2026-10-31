<?php

namespace Swage\SecurityScanner;

use App\Enums\ResourceStatus;
use App\Models\Server;
use Illuminate\Database\Eloquent\Collection;
use Swage\SecurityScanner\Enums\AlertSeverity;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\Fail2banBan;
use Swage\SecurityScanner\Models\SecurityAlert;

/**
 * The open alerts the security panel lists on each server, leaving out addresses fail2ban has banned or that are
 * blocked. Servers are read together, in the same few queries however many there are.
 */
class NeedsAttention
{
    /**
     * @param  Collection<int, Server>  $servers
     * @return array<int, array{alerts: int, severity: AlertSeverity}> By server id. Servers with nothing to look at are left out.
     */
    public function for(Collection $servers): array
    {
        $ids = $servers->modelKeys();

        if ($ids === []) {
            return [];
        }

        $alerts = SecurityAlert::query()->whereIn('server_id', $ids)->open()->get(['server_id', 'subject', 'severity']);
        $blocked = BlockedAddress::query()->whereIn('server_id', $ids)->where('status', ResourceStatus::Installed)->get(['server_id', 'ip'])->groupBy('server_id');
        $bans = Fail2banBan::query()->whereIn('server_id', $alerts->pluck('server_id')->unique())->whereIn('ip', $alerts->pluck('subject')->unique())
            ->get(['server_id', 'ip'])->groupBy('server_id');
        $items = [];

        $alerts->groupBy('server_id')
            ->each(function (Collection $alerts, int $serverId) use ($bans, $blocked, &$items): void {
                $banned = [...$bans->get($serverId)?->pluck('ip') ?? [], ...$blocked->get($serverId)?->pluck('ip') ?? []];

                foreach ($alerts->reject(fn (SecurityAlert $alert): bool => in_array($alert->subject, $banned, true)) as $alert) {
                    $items[$serverId] ??= ['alerts' => 0, 'severity' => $alert->severity];
                    $items[$serverId]['alerts']++;

                    if ($alert->severity->rank() > $items[$serverId]['severity']->rank()) {
                        $items[$serverId]['severity'] = $alert->severity;
                    }
                }
            });

        return $items;
    }
}
