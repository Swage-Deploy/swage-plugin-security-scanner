<?php

namespace Swage\SecurityScanner\Scanning;

use App\Models\Server;
use Carbon\CarbonInterface;
use Swage\SecurityScanner\Enums\AlertRule;
use Swage\SecurityScanner\Events\AlertRaised;
use Swage\SecurityScanner\Models\SecurityAlert;

/**
 * Opens an alert, or counts another occurrence on the open alert the same rule raised for the same subject.
 */
class AlertRaiser
{
    /**
     * @param  array<string, mixed>  $details
     */
    public function raise(Server $server, AlertRule $rule, string $subject, array $details, CarbonInterface $seenAt, int $occurrences = 1): SecurityAlert
    {
        $alert = SecurityAlert::query()
            ->where('server_id', $server->id)
            ->where('rule', $rule)
            ->where('subject', $subject)
            ->open()
            ->first();

        if ($alert) {
            $alert->update([
                'details' => [...$alert->details ?? [], ...$details],
                'occurrences' => $alert->occurrences + $occurrences,
                'last_seen_at' => $seenAt->gt($alert->last_seen_at) ? $seenAt : $alert->last_seen_at,
            ]);

            return $alert;
        }

        $alert = SecurityAlert::create([
            'server_id' => $server->id,
            'rule' => $rule,
            'severity' => $rule->severity(),
            'subject' => $subject,
            'details' => $details,
            'occurrences' => $occurrences,
            'first_seen_at' => $seenAt,
            'last_seen_at' => $seenAt,
        ]);

        AlertRaised::dispatch($alert);

        return $alert;
    }
}
