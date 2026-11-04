<?php

namespace Swage\SecurityScanner\Listeners;

use App\Notifications\ServerAlert;
use Swage\SecurityScanner\Events\AlertRaised;

/**
 * Tells the server's owner and Managers about each new alert, in the panel, by email and on the server's webhooks.
 * Needs Swage v1.3.16, so the provider only listens when ServerAlert exists.
 */
class SendAlertNotification
{
    public function handle(AlertRaised $event): void
    {
        $alert = $event->alert;

        ServerAlert::send(
            server: $alert->server,
            source: __('Security scanner'),
            title: $alert->rule->title(),
            message: "{$alert->subject}: {$alert->summary()}",
            severity: $alert->severity->value,
            link: route('servers.plugins', ['server' => $alert->server_id, 'plugin' => 'security-scanner']),
        );
    }
}
