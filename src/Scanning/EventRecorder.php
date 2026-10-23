<?php

namespace Swage\SecurityScanner\Scanning;

use App\Models\Server;
use Illuminate\Support\Collection;
use Swage\SecurityScanner\Models\SecurityEvent;

/**
 * Counts events into one row per kind, address, source and hour, so busy logs never store a row per line.
 */
class EventRecorder
{
    /**
     * @param  list<LogEvent>  $events
     */
    public function record(Server $server, array $events): void
    {
        collect($events)
            ->groupBy(fn (LogEvent $event): string => implode('|', [
                $event->kind->value,
                $event->ip ?? '',
                $event->source,
                $event->occurredAt->utc()->startOfHour()->toIso8601String(),
            ]))
            ->each(fn (Collection $group) => $this->increment($server, $group));
    }

    /**
     * @param  Collection<int, LogEvent>  $group
     */
    protected function increment(Server $server, Collection $group): void
    {
        /** @var LogEvent $first */
        $first = $group->first();

        $row = SecurityEvent::firstOrNew([
            'server_id' => $server->id,
            'kind' => $first->kind,
            'ip' => $first->ip,
            'source' => $first->source,
            'bucket' => $first->occurredAt->utc()->startOfHour(),
        ]);

        $earliest = $group->min(fn (LogEvent $event) => $event->occurredAt);
        $latest = $group->max(fn (LogEvent $event) => $event->occurredAt);

        $row->fill([
            'count' => $row->count + $group->count(),
            'targets' => collect($row->targets ?? [])
                ->merge($group->pluck('target')->filter())
                ->unique()
                ->take(SecurityEvent::MAX_TARGETS)
                ->values()
                ->all(),
            'first_seen_at' => $row->first_seen_at && $row->first_seen_at->lt($earliest) ? $row->first_seen_at : $earliest,
            'last_seen_at' => $row->last_seen_at && $row->last_seen_at->gt($latest) ? $row->last_seen_at : $latest,
        ])->save();
    }
}
