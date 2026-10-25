<?php

namespace Swage\SecurityScanner\Scanning;

use App\Models\Server;
use Swage\SecurityScanner\Enums\AlertRule;
use Swage\SecurityScanner\Enums\EventKind;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityEvent;

/**
 * Raises alerts from the SSH logins a scan read, once they are recorded. Brute force attempts and probing are only
 * counted, and fail2ban bans the addresses behind them.
 */
class ThreatDetector
{
    public function __construct(protected AlertRaiser $alerts) {}

    /**
     * A login from an address that failed to log in during the day before is the strongest sign a password or key
     * was guessed. Otherwise, a login from an address the server has not been logged into from before is worth a
     * look, once the first scan has learned where logins usually come from.
     *
     * @param  list<LogEvent>  $events
     */
    public function detect(ScannerState $state, array $events): void
    {
        $server = $state->server;
        $hasBaseline = $state->hasBaseline();

        foreach ($events as $event) {
            if ($event->kind !== EventKind::SshLogin) {
                continue;
            }

            $failures = $this->failuresBefore($server, $event);

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
     * Count the address's failed SSH logins during the day before it logged in.
     */
    protected function failuresBefore(Server $server, LogEvent $event): int
    {
        return (int) SecurityEvent::query()
            ->where('server_id', $server->id)
            ->where('ip', $event->ip)
            ->whereIn('kind', EventKind::sshAttempts())
            ->where('last_seen_at', '>=', $event->occurredAt->subDay())
            ->where('first_seen_at', '<=', $event->occurredAt)
            ->sum('count');
    }
}
