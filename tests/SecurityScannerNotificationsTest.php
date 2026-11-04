<?php

use App\Models\Server;
use App\Notifications\ServerAlert;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Notification;
use Swage\SecurityScanner\Enums\AlertRule;
use Swage\SecurityScanner\Scanning\AlertRaiser;
use Swage\SecurityScanner\SecurityScannerServiceProvider;

beforeEach(function () {
    $this->app->register(SecurityScannerServiceProvider::class, force: true);
    $this->artisan('migrate', ['--path' => dirname((new ReflectionClass(SecurityScannerServiceProvider::class))->getFileName(), 2).'/database/migrations', '--realpath' => true]);
});

test('each new alert notifies the server\'s owner once, linking to the scanner\'s tab', function () {
    Notification::fake();
    $server = Server::factory()->create(['name' => 'production-1']);
    $raiser = app(AlertRaiser::class);

    $raiser->raise($server, AlertRule::SshLoginAfterFailures, '203.0.113.9', ['user' => 'root', 'failed_attempts' => 12], CarbonImmutable::now());
    $raiser->raise($server, AlertRule::SshLoginAfterFailures, '203.0.113.9', ['user' => 'root', 'failed_attempts' => 14], CarbonImmutable::now());

    Notification::assertSentToTimes($server->user, ServerAlert::class, 1);
    Notification::assertSentTo($server->user, ServerAlert::class, fn (ServerAlert $alert) => $alert->severity() === 'high'
        && str_starts_with($alert->message(), '203.0.113.9: Logged in as root after 12 failed attempts')
        && $alert->url() === route('servers.plugins', ['server' => $server, 'plugin' => 'security-scanner']));
});
