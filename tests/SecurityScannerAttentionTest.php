<?php

use App\Enums\ResourceStatus;
use App\Models\Server;
use App\Plugins\Attention;
use App\Plugins\HasAttention;
use App\Servers\ServerIntegrations;
use Illuminate\Database\Eloquent\Collection;
use Swage\SecurityScanner\Enums\AlertRule;
use Swage\SecurityScanner\Enums\AlertSeverity;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\Fail2banBan;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\SecurityScannerServiceProvider;

beforeEach(function () {
    $this->app->register(SecurityScannerServiceProvider::class, force: true);
    $this->artisan('migrate', ['--path' => dirname((new ReflectionClass(SecurityScannerServiceProvider::class))->getFileName(), 2).'/database/migrations', '--realpath' => true]);

    $this->travelTo('2026-10-28 12:00:00');
});

function attentionAlert(Server $server, string $ip, AlertSeverity $severity = AlertSeverity::Low, array $attributes = []): SecurityAlert
{
    return SecurityAlert::create([
        'server_id' => $server->id,
        'rule' => $severity === AlertSeverity::High ? AlertRule::SshLoginAfterFailures : AlertRule::SshLoginNewAddress,
        'severity' => $severity,
        'subject' => $ip,
        'details' => ['user' => 'deploy'],
        'occurrences' => 1,
        'first_seen_at' => now(),
        'last_seen_at' => now(),
        ...$attributes,
    ]);
}

function attentionFor(Server ...$servers): array
{
    return app(ServerIntegrations::class)->all()['security-scanner']->attention(new Collection($servers));
}

test('the scanner says which servers have open alerts to look at', function () {
    expect(app(ServerIntegrations::class)->all()['security-scanner'])->toBeInstanceOf(HasAttention::class);

    $quiet = Server::factory()->create();
    $server = Server::factory()->create();
    Fail2banBan::sync($server->id, ['203.0.113.5']);

    attentionAlert($server, '198.51.100.1');
    attentionAlert($server, '198.51.100.2', attributes: ['resolved_at' => now()]);
    attentionAlert($server, '203.0.113.5', AlertSeverity::High);
    attentionAlert($server, '203.0.113.6', AlertSeverity::High);
    BlockedAddress::create(['server_id' => $server->id, 'ip' => '203.0.113.6', 'status' => ResourceStatus::Installed]);

    $attention = attentionFor($quiet, $server);

    // The one open alert that isn't banned or blocked.
    expect($attention)->toHaveKeys([$server->id])->not->toHaveKey($quiet->id)
        ->and($attention[$server->id]->count)->toBe(1)
        ->and($attention[$server->id]->severity)->toBe(Attention::LOW)
        ->and($attention[$server->id]->label)->toBe('Security scanner: 1 open SSH login alert');
});

test('low severity alerts still get a badge, in grey', function () {
    $server = Server::factory()->create();
    attentionAlert($server, '198.51.100.1');
    attentionAlert($server, '198.51.100.3');

    $attention = attentionFor($server)[$server->id];

    expect($attention->count)->toBe(2)
        ->and($attention->severity)->toBe(Attention::LOW)
        ->and($attention->color())->toBe('zinc')
        ->and($attention->label)->toBe('Security scanner: 2 open SSH login alerts');
});

test('the servers page badges a server with something to look at', function () {
    $server = Server::factory()->create();
    attentionAlert($server, '198.51.100.1', AlertSeverity::High);

    $this->actingAs($server->user)->get(route('dashboard'))
        ->assertOk()
        ->assertSee('title="Security scanner: 1 open SSH login alert"', false);

    $this->actingAs($server->user)->get(route('servers.show', $server))
        ->assertOk()
        ->assertSee('bg-red-400/20 dark:bg-red-400/40 ms-2">1', false);

    SecurityAlert::query()->update(['resolved_at' => now()]);

    $this->actingAs($server->user)->get(route('dashboard'))
        ->assertOk()
        ->assertDontSee('Security scanner: 1 open SSH login alert');
});
