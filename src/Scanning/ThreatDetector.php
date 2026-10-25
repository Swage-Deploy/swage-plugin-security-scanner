<?php

namespace Swage\SecurityScanner\Scanning;

use App\Models\Server;
use Carbon\CarbonImmutable;
use Swage\SecurityScanner\Enums\AlertRule;
use Swage\SecurityScanner\Enums\EventKind;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityEvent;

/**
 * Raises alerts from the events a scan read, once they are recorded.
 *
 * Counts are judged over the last hour of recorded events, but only for addresses active in this scan, so an alert
 * stops counting up once its address goes quiet.
 */
class ThreatDetector
{
    public function __construct(protected AlertRaiser $alerts) {}

    /**
     * @param  list<LogEvent>  $events
     */
    public function detect(ScannerState $state, array $events): void
    {
        $server = $state->server;

        $this->logins($server, $events, $state->hasBaseline());
        $this->sudoFailures($server, $events);

        $thresholds = config('security-scanner.thresholds');

        $this->threshold($server, $events, AlertRule::SshBruteForce, EventKind::sshAttempts(), $thresholds['ssh_attempts']);
        $this->threshold($server, $events, AlertRule::HttpProbing, [EventKind::HttpProbe], $thresholds['http_probes']);
        $this->threshold($server, $events, AlertRule::HttpLoginBruteForce, [EventKind::HttpLogin], $thresholds['http_logins']);
    }

    /**
     * A login from an address that failed to log in during the day before is the strongest sign a password or key
     * was guessed. Otherwise, a login from an address the server has not been logged into from before is worth a
     * look, once the first scan has learned where logins usually come from.
     *
     * @param  list<LogEvent>  $events
     */
    protected function logins(Server $server, array $events, bool $hasBaseline): void
    {
        foreach ($events as $event) {
            if ($event->kind !== EventKind::SshLogin) {
                continue;
            }

            $failures = (int) SecurityEvent::query()
                ->where('server_id', $server->id)
                ->where('ip', $event->ip)
                ->whereIn('kind', EventKind::sshAttempts())
                ->where('last_seen_at', '>=', $event->occurredAt->subDay())
                ->where('first_seen_at', '<=', $event->occurredAt)
                ->sum('count');

            if ($failures > 0) {
                $this->alerts->raise($server, AlertRule::SshLoginAfterFailures, $event->ip, [
                    'user' => $event->target,
                    'failed_attempts' => $failures,
                ], $event->occurredAt);

                continue;
            }

            $seenBefore = SecurityEvent::query()
                ->where('server_id', $server->id)
                ->where('ip', $event->ip)
                ->where('kind', EventKind::SshLogin)
                ->where('first_seen_at', '<', $event->occurredAt)
                ->exists();

            if ($hasBaseline && ! $seenBefore) {
                $this->alerts->raise($server, AlertRule::SshLoginNewAddress, $event->ip, ['user' => $event->target], $event->occurredAt);
            }
        }
    }

    /**
     * @param  list<LogEvent>  $events
     */
    protected function sudoFailures(Server $server, array $events): void
    {
        collect($events)
            ->filter(fn (LogEvent $event): bool => $event->kind === EventKind::SudoFailed)
            ->groupBy('target')
            ->each(fn ($failures, string $user) => $this->alerts->raise(
                $server,
                AlertRule::SudoFailure,
                $user,
                ['user' => $user],
                $failures->max('occurredAt'),
                $failures->count(),
            ));
    }

    /**
     * @param  list<LogEvent>  $events
     * @param  list<EventKind>  $kinds
     */
    protected function threshold(Server $server, array $events, AlertRule $rule, array $kinds, int $threshold): void
    {
        $addresses = collect($events)
            ->filter(fn (LogEvent $event): bool => in_array($event->kind, $kinds, true) && $event->ip !== null)
            ->pluck('ip')
            ->unique();

        foreach ($addresses as $ip) {
            $rows = SecurityEvent::query()
                ->where('server_id', $server->id)
                ->where('ip', $ip)
                ->whereIn('kind', $kinds)
                ->where('last_seen_at', '>=', now()->subHour())
                ->get();

            $count = (int) $rows->sum('count');

            if ($count < $threshold) {
                continue;
            }

            $this->alerts->raise($server, $rule, $ip, [
                'count' => $count,
                'targets' => $rows->flatMap(fn (SecurityEvent $row): array => $row->targets ?? [])->unique()->take(10)->values()->all(),
                'sources' => $rows->pluck('source')->unique()->values()->all(),
            ], CarbonImmutable::instance($rows->max('last_seen_at')));
        }
    }
}
