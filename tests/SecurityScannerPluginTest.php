<?php

use App\Enums\ResourceStatus;
use App\Enums\ServerStatus;
use App\Models\Server;
use App\Models\User;
use App\Servers\ServerIntegrations;
use App\Sites\CloudflareNetworks;
use App\Ssh\RemoteShell;
use App\Ssh\ScriptResult;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Queue;
use Livewire\Livewire;
use Swage\SecurityScanner\CloudflareAddresses;
use Swage\SecurityScanner\Enums\AlertRule;
use Swage\SecurityScanner\Enums\AlertSeverity;
use Swage\SecurityScanner\Enums\EventKind;
use Swage\SecurityScanner\Events\AlertRaised;
use Swage\SecurityScanner\Jobs\BlockAddress;
use Swage\SecurityScanner\Jobs\InstallFail2ban;
use Swage\SecurityScanner\Jobs\ScanServerLogs;
use Swage\SecurityScanner\Jobs\UnblockAddress;
use Swage\SecurityScanner\Livewire\SecurityPanel;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;
use Swage\SecurityScanner\Scanning\LogScanner;
use Swage\SecurityScanner\Scanning\NginxAccessParser;
use Swage\SecurityScanner\Scanning\ScannedFile;
use Swage\SecurityScanner\Scanning\ScanScript;
use Swage\SecurityScanner\Scanning\SshLogParser;
use Swage\SecurityScanner\SecurityScannerServiceProvider;

beforeEach(function () {
    $this->app->register(SecurityScannerServiceProvider::class, force: true);
    $this->artisan('migrate', ['--path' => dirname((new ReflectionClass(SecurityScannerServiceProvider::class))->getFileName(), 2).'/database/migrations', '--realpath' => true]);

    $this->travelTo('2026-10-23 12:00:00');
});

/**
 * A server standing in for a real one, answering the scan script with the logs given, framed by the script's marker.
 */
class ScannedServer implements RemoteShell
{
    /**
     * @var list<string>
     */
    public array $scripts = [];

    /**
     * @param  list<string>  $journal
     * @param  array<string, array{inode: int, start: int, new: bool, content: string}>  $files
     */
    public function __construct(
        public array $journal = [],
        public array $files = [],
        public string $client = '198.51.100.1',
        public ?string $cursor = 's=abc;i=10',
        public ?string $banned = null,
        public int $exitCode = 0,
        public ?array $denied = null,
    ) {}

    public function run(Server $server, string $script, ?string $as = null, int $timeout = 600, ?Closure $onOutput = null): ScriptResult
    {
        $this->scripts[] = $script;

        if (! preg_match("/^marker='(@@SWAGE_SCAN_\w+)'/m", $script, $matches)) {
            return new ScriptResult(exitCode: 0, output: 'ok');
        }

        $marker = $matches[1];
        $output = "\n{$marker} client {$this->client}\n";
        $output .= "\n{$marker} journal\n".implode("\n", $this->journal).($this->cursor ? "\n-- cursor: {$this->cursor}" : '')."\n";
        $output .= "\n{$marker} fail2ban\n".($this->banned === null ? '' : "installed\n{$this->banned}\n");
        $output .= "\n{$marker} nginx-deny\n".($this->denied === null ? '' : implode("\n", ['present', ...$this->denied])."\n");

        foreach ($this->files as $path => $file) {
            $output .= "\n{$marker} nginx {$file['inode']} {$file['start']} ".($file['new'] ? 'new' : 'known')." {$path}\n{$file['content']}";
        }

        return new ScriptResult(exitCode: $this->exitCode, output: $output."\n{$marker} end\n");
    }

    public function stream(Server $server, string $script, Closure $onOutput, int $timeout = 600): ScriptResult
    {
        return $this->run($server, $script, timeout: $timeout);
    }

    public function upload(Server $server, string $localPath, string $remotePath): void {}
}

function scannedServer(...$arguments): ScannedServer
{
    return tap(new ScannedServer(...$arguments), fn (ScannedServer $shell) => app()->instance(RemoteShell::class, $shell));
}

function sshLine(string $message, string $time = '2026-10-23T11:58:00+00:00'): string
{
    return "{$time} web-1 sshd[1234]: {$message}";
}

function accessLine(string $ip, string $request, int $status = 404, string $time = '23/Oct/2026:11:58:00 +0000'): string
{
    return "{$ip} - - [{$time}] \"{$request}\" {$status} 162 \"-\" \"Mozilla/5.0\"";
}

function scan(Server $server): ScannerState
{
    $state = ScannerState::for($server);
    $state->update(['enabled' => true]);

    app(LogScanner::class)->scan($state->fresh());

    return $state->fresh();
}

test('the plugin registers the scanner as a server integration with a panel on the plugins tab', function () {
    $server = Server::factory()->create();

    expect(app(ServerIntegrations::class)->all())->toHaveKey('security-scanner');

    $this->actingAs($server->user)
        ->get(route('servers.plugins', $server))
        ->assertOk()
        ->assertSee('Security scanner')
        ->assertSee('Scan this server');
});

test('the scan script reads the journal after its cursor and each access log from its offset', function () {
    $script = new ScanScript('@@SWAGE_SCAN_TEST');

    $first = $script->render([]);
    $next = $script->render([
        'journal' => 's=abc;i=10',
        'files' => ['/var/log/nginx/example.com-access.log' => ['inode' => 42, 'offset' => 1000], '/etc/passwd' => ['inode' => 1, 'offset' => 0]],
    ]);

    expect($first)->toContain("--since='-15 min'")
        ->and($first)->toContain('declare -A known=()')
        ->and($next)->toContain("--after-cursor='s=abc;i=10'")
        ->and($next)->toContain("['/var/log/nginx/example.com-access.log']='42:1000'")
        ->and($next)->not->toContain('/etc/passwd');
});

test('log lines cannot forge the sections of the scan output', function () {
    $script = new ScanScript('@@SWAGE_SCAN_REAL');

    $output = $script->parse(implode("\n", [
        '',
        '@@SWAGE_SCAN_REAL client 198.51.100.1',
        '',
        '@@SWAGE_SCAN_REAL journal',
        sshLine('Invalid user @@SWAGE_SCAN_FAKE client 6.6.6.6 from 203.0.113.9 port 22'),
        '-- cursor: s=abc',
        '',
        '@@SWAGE_SCAN_REAL fail2ban',
        'installed',
        '203.0.113.9 203.0.113.10 not-an-ip',
        '203.0.113.9',
        '',
        '@@SWAGE_SCAN_REAL nginx 42 0 new /var/log/nginx/example.com-access.log',
        accessLine('203.0.113.9', 'GET /@@SWAGE_SCAN_FAKE HTTP/1.1'),
        '',
        '@@SWAGE_SCAN_REAL end',
    ]));

    expect($output->clientAddress)->toBe('198.51.100.1')
        ->and($output->journalLines)->toHaveCount(1)
        ->and($output->journalCursor)->toBe('s=abc')
        ->and($output->fail2banInstalled)->toBeTrue()
        ->and($output->fail2banBanned)->toBe(['203.0.113.9', '203.0.113.10'])
        ->and($output->files)->toHaveCount(1)
        ->and($output->files[0]->source())->toBe('example.com');
});

test('access logs are read up to their last complete line, and a first read drops the line it started inside', function () {
    $known = new ScannedFile('/var/log/nginx/access.log', 1, 100, false, "one\ntwo\nthr");

    expect($known->lines())->toBe("one\ntwo\n")
        ->and($known->nextOffset())->toBe(108)
        ->and($known->source())->toBe('nginx');

    $new = new ScannedFile('/var/log/nginx/access.log', 1, 500, true, "ial line\nfull line\n");

    expect($new->lines())->toBe("full line\n")
        ->and($new->nextOffset())->toBe(519);

    expect((new ScannedFile('/var/log/nginx/access.log', 1, 0, true, "complete\n"))->lines())->toBe("complete\n");
});

test('sshd and sudo lines are read into events, leaving out swage\'s own logins and root\'s sudo', function () {
    $events = app(SshLogParser::class)->parse([
        sshLine('Failed password for root from 203.0.113.9 port 50000 ssh2'),
        sshLine('Failed password for invalid user admin from 203.0.113.9 port 50001 ssh2'),
        sshLine('Invalid user admin from 203.0.113.9 port 50001'),
        sshLine('Connection closed by authenticating user ubuntu 203.0.113.10 port 50002 [preauth]'),
        sshLine('Accepted publickey for root from 198.51.100.1 port 50003 ssh2: ED25519 SHA256:abc'),
        sshLine('Accepted publickey for swage from 2001:db8::7 port 50004 ssh2: ED25519 SHA256:abc'),
        '2026-10-23T11:58:00+00:00 web-1 sudo[99]:     root : PWD=/root ; USER=swage ; COMMAND=/usr/bin/bash -s',
        '2026-10-23T11:58:00+00:00 web-1 sudo[99]:    swage : TTY=pts/0 ; PWD=/home/swage ; USER=root ; COMMAND=/usr/bin/ls',
        '2026-10-23T11:58:00+00:00 web-1 sudo[99]:    swage : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/swage ; USER=root ; COMMAND=/usr/bin/ls',
        'not a journal line',
    ], ignoreAddress: '198.51.100.1');

    expect(collect($events)->map(fn ($event) => [$event->kind, $event->ip, $event->target])->all())->toBe([
        [EventKind::SshFailedLogin, '203.0.113.9', 'root'],
        [EventKind::SshInvalidUser, '203.0.113.9', 'admin'],
        [EventKind::SshFailedLogin, '203.0.113.10', 'ubuntu'],
        [EventKind::SshLogin, '2001:db8::7', 'swage'],
        [EventKind::SudoCommand, null, 'swage'],
        [EventKind::SudoFailed, null, 'swage'],
    ]);
});

test('only probes, login submissions, denied and missing requests are counted from access logs', function () {
    $events = app(NginxAccessParser::class)->parse(implode("\n", [
        accessLine('203.0.113.9', 'GET /.env HTTP/1.1'),
        accessLine('203.0.113.9', 'GET /wp-login.php HTTP/1.1'),
        accessLine('203.0.113.9', 'GET /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1'),
        accessLine('203.0.113.10', 'POST /login HTTP/1.1', 302),
        accessLine('203.0.113.11', 'GET /admin HTTP/1.1', 403),
        accessLine('203.0.113.12', 'GET /missing HTTP/1.1', 404),
        accessLine('203.0.113.13', 'GET /index.php?page=1 HTTP/1.1', 200),
        accessLine('203.0.113.13', 'GET /dashboard HTTP/1.1', 200),
        accessLine('203.0.113.14', '\x16\x03\x01\x00', 400),
        'garbage',
    ]), 'example.com');

    expect(collect($events)->map(fn ($event) => [$event->kind, $event->ip])->all())->toBe([
        [EventKind::HttpProbe, '203.0.113.9'],
        [EventKind::HttpProbe, '203.0.113.9'],
        [EventKind::HttpProbe, '203.0.113.9'],
        [EventKind::HttpLogin, '203.0.113.10'],
        [EventKind::HttpDenied, '203.0.113.11'],
        [EventKind::HttpNotFound, '203.0.113.12'],
    ])->and($events[0]->source)->toBe('example.com');
});

test('a scan counts events per address and hour, raises no alert for brute force attempts, and remembers where it stopped', function () {
    Event::fake([AlertRaised::class]);
    $server = Server::factory()->create();

    $content = accessLine('203.0.113.20', 'GET /.git/config HTTP/1.1')."\n";
    scannedServer(
        journal: [
            ...array_fill(0, 25, sshLine('Failed password for root from 203.0.113.9 port 50000 ssh2')),
            sshLine('Accepted publickey for root from 198.51.100.1 port 50003 ssh2: ED25519 SHA256:abc'),
        ],
        files: ['/var/log/nginx/example.com-access.log' => ['inode' => 42, 'start' => 0, 'new' => true, 'content' => $content.'partial']],
        banned: '203.0.113.9',
    );

    $state = scan($server);

    expect(SecurityEvent::where('kind', EventKind::SshFailedLogin)->sole())
        ->ip->toBe('203.0.113.9')
        ->count->toBe(25)
        ->targets->toBe(['root'])
        ->and(SecurityEvent::where('kind', EventKind::SshLogin)->exists())->toBeFalse()
        ->and(SecurityEvent::where('kind', EventKind::HttpProbe)->sole()->source)->toBe('example.com');

    expect(SecurityAlert::count())->toBe(0);

    expect($state)
        ->panel_address->toBe('198.51.100.1')
        ->fail2ban_installed->toBeTrue()
        ->fail2ban_banned->toBe(['203.0.113.9'])
        ->last_error->toBeNull()
        ->cursors->toBe([
            'journal' => 's=abc;i=10',
            'files' => ['/var/log/nginx/example.com-access.log' => ['inode' => 42, 'offset' => strlen($content)]],
        ]);

    Event::assertNotDispatched(AlertRaised::class);
});

test('further logins from an address count on its open alert rather than opening another', function () {
    Event::fake([AlertRaised::class]);
    $server = Server::factory()->create();
    $login = fn (string $time) => sshLine('Accepted password for deploy from 203.0.113.9 port 50001 ssh2', $time);

    scannedServer(journal: [
        sshLine('Failed password for deploy from 203.0.113.9 port 50000 ssh2', '2026-10-23T11:50:00+00:00'),
        $login('2026-10-23T11:52:00+00:00'),
    ]);
    scan($server);

    scannedServer(journal: [$login('2026-10-23T11:55:00+00:00')]);
    scan($server);

    expect(SecurityAlert::sole())
        ->rule->toBe(AlertRule::SshLoginAfterFailures)
        ->occurrences->toBe(2);

    Event::assertDispatchedTimes(AlertRaised::class, 1);

    SecurityAlert::sole()->resolve();
    scan($server);

    expect(SecurityAlert::count())->toBe(2);
});

test('fail2ban\'s jails and the addresses they banned are read from the scan', function () {
    $server = Server::factory()->create();

    scannedServer(banned: "jails sshd, recidive\n203.0.113.9\n203.0.113.10 203.0.113.9");
    $state = scan($server);

    expect($state)
        ->fail2ban_jails->toBe(['sshd', 'recidive'])
        ->fail2ban_banned->toBe(['203.0.113.9', '203.0.113.10']);
});

test('servers whose fail2ban has no probes jail are offered an update once they have sites\' logs', function (?array $jails, array $files, bool $needsUpdate) {
    $server = Server::factory()->create();
    $state = tap(ScannerState::for($server))->update(['last_scanned_at' => now(), 'fail2ban_installed' => true, 'fail2ban_jails' => $jails, 'cursors' => ['journal' => null, 'files' => $files]]);

    expect($state->fresh()->needsFail2banUpdate())->toBe($needsUpdate);

    $panel = Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server]);
    $needsUpdate ? $panel->assertSee('Update fail2ban') : $panel->assertDontSee('Update fail2ban');
})->with([
    'no probes jail' => [['sshd', 'recidive'], ['/var/log/nginx/access.log' => ['inode' => 1, 'offset' => 0]], true],
    'probes jail' => [['sshd', 'recidive', 'swage-probes'], ['/var/log/nginx/access.log' => ['inode' => 1, 'offset' => 0]], false],
    'no nginx' => [['sshd', 'recidive'], [], false],
    'jails not read yet' => [null, ['/var/log/nginx/access.log' => ['inode' => 1, 'offset' => 0]], false],
]);

test('servers whose fail2ban could ban swage\'s own address are offered an update', function () {
    $server = Server::factory()->create();

    scannedServer(banned: "jails sshd, recidive, swage-probes\nignores-panel no\n203.0.113.9");
    $state = scan($server);

    expect($state)
        ->fail2ban_ignores_panel->toBeFalse()
        ->fail2ban_banned->toBe(['203.0.113.9'])
        ->and($state->needsFail2banUpdate())->toBeTrue();

    Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->assertSee('fail2ban could lock Swage out of this server')
        ->assertSee('Update fail2ban');

    scannedServer(banned: "jails sshd, recidive, swage-probes\nignores-panel yes\n203.0.113.9");

    expect(scan($server))
        ->fail2ban_ignores_panel->toBeTrue()
        ->and(ScannerState::for($server)->needsFail2banUpdate())->toBeFalse();
});

test('servers whose recidive jail can\'t see fail2ban\'s bans are offered an update', function () {
    $server = Server::factory()->create();

    scannedServer(banned: "jails sshd, recidive, swage-probes\nignores-panel yes\nrecidive-reads-log no\n203.0.113.9");
    $state = scan($server);

    expect($state)
        ->fail2ban_recidive_reads_log->toBeFalse()
        ->fail2ban_banned->toBe(['203.0.113.9'])
        ->and($state->needsFail2banUpdate())->toBeTrue();

    Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->assertSee('fail2ban never bans addresses for a week')
        ->assertSee('Update fail2ban');

    scannedServer(banned: "jails sshd, recidive, swage-probes\nignores-panel yes\nrecidive-reads-log yes\n203.0.113.9");

    expect(scan($server))
        ->fail2ban_recidive_reads_log->toBeTrue()
        ->and(ScannerState::for($server)->needsFail2banUpdate())->toBeFalse();
});

test('servers whose sshd jail only counts failed logins over ten minutes are offered an update', function () {
    $server = Server::factory()->create();

    scannedServer(banned: "jails sshd, recidive, swage-probes\nignores-panel yes\nrecidive-reads-log yes\nsshd-counts-hour no\n203.0.113.9");
    $state = scan($server);

    expect($state)
        ->fail2ban_sshd_counts_hour->toBeFalse()
        ->fail2ban_banned->toBe(['203.0.113.9'])
        ->and($state->needsFail2banUpdate())->toBeTrue();

    Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->assertSee('fail2ban misses slow SSH attacks')
        ->assertSee('Update fail2ban');

    scannedServer(banned: "jails sshd, recidive, swage-probes\nignores-panel yes\nrecidive-reads-log yes\nsshd-counts-hour yes\n203.0.113.9");

    expect(scan($server))
        ->fail2ban_sshd_counts_hour->toBeTrue()
        ->and(ScannerState::for($server)->needsFail2banUpdate())->toBeFalse();
});

test('the scan script asks whether fail2ban\'s sshd jail counts failed logins over an hour', function () {
    expect((new ScanScript('@@M'))->render([]))->toContain('[ "$(fail2ban-client get sshd findtime 2>/dev/null)" -ge 3600 ] 2>/dev/null && echo \'sshd-counts-hour yes\' || echo \'sshd-counts-hour no\'');
});

test('the scan script asks whether fail2ban\'s recidive jail reads its log', function () {
    expect((new ScanScript('@@M'))->render([]))->toContain("fail2ban-client status recidive 2>/dev/null | grep -q 'File list' && echo 'recidive-reads-log yes' || echo 'recidive-reads-log no'");
});

test('the scan script asks whether fail2ban leaves swage\'s address alone', function () {
    expect((new ScanScript('@@M'))->render([]))->toContain("grep -qs '^ignoreip = ' /etc/fail2ban/jail.d/swage.conf && echo 'ignores-panel yes' || echo 'ignores-panel no'");
});

test('alerts about addresses fail2ban has banned or that are blocked are left out of the open alerts', function () {
    $server = Server::factory()->create();
    ScannerState::for($server)->update(['last_scanned_at' => now(), 'fail2ban_installed' => true, 'fail2ban_banned' => ['203.0.113.9']]);
    BlockedAddress::create(['server_id' => $server->id, 'ip' => '203.0.113.10', 'status' => ResourceStatus::Installed]);
    BlockedAddress::create(['server_id' => $server->id, 'ip' => '203.0.113.11', 'status' => ResourceStatus::Failed]);

    foreach (['203.0.113.9', '203.0.113.10', '203.0.113.11', '203.0.113.12'] as $ip) {
        SecurityAlert::create(['server_id' => $server->id, 'rule' => AlertRule::SshLoginNewAddress, 'severity' => AlertSeverity::Low, 'subject' => $ip, 'details' => ['user' => 'deploy'], 'first_seen_at' => now(), 'last_seen_at' => now()]);
    }

    $alerts = Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])->get('alerts');

    expect($alerts->pluck('subject')->sort()->values()->all())->toBe(['203.0.113.11', '203.0.113.12']);
});

test('a login from an address that was failing to log in raises a high alert', function () {
    $server = Server::factory()->create();

    scannedServer(journal: [
        sshLine('Failed password for deploy from 203.0.113.9 port 50000 ssh2', '2026-10-23T11:50:00+00:00'),
        sshLine('Failed password for deploy from 203.0.113.9 port 50000 ssh2', '2026-10-23T11:51:00+00:00'),
        sshLine('Accepted password for deploy from 203.0.113.9 port 50001 ssh2', '2026-10-23T11:52:00+00:00'),
    ]);

    scan($server);

    expect(SecurityAlert::sole())
        ->rule->toBe(AlertRule::SshLoginAfterFailures)
        ->severity->toBe(AlertSeverity::High)
        ->details->toMatchArray(['user' => 'deploy', 'failed_attempts' => 2]);
});

test('logins from new addresses are only flagged once the first scan has learned the usual ones', function () {
    $server = Server::factory()->create();

    scannedServer(journal: [sshLine('Accepted publickey for swage from 192.0.2.5 port 50000 ssh2')]);
    scan($server);

    expect(SecurityAlert::count())->toBe(0);

    $this->travel(5)->minutes();
    scannedServer(journal: [
        sshLine('Accepted publickey for swage from 192.0.2.5 port 50000 ssh2', '2026-10-23T12:03:00+00:00'),
        sshLine('Accepted publickey for swage from 192.0.2.99 port 50000 ssh2', '2026-10-23T12:03:00+00:00'),
    ]);
    scan($server);

    expect(SecurityAlert::sole())
        ->rule->toBe(AlertRule::SshLoginNewAddress)
        ->subject->toBe('192.0.2.99');
});

test('the next scan continues from the saved cursors, and a refused journal cursor starts again from recent history', function () {
    $server = Server::factory()->create();
    ScannerState::for($server)->update([
        'last_scanned_at' => now(),
        'cursors' => ['journal' => 's=old', 'files' => ['/var/log/nginx/access.log' => ['inode' => 1, 'offset' => 500]]],
    ]);

    $shell = scannedServer(cursor: null);
    $state = scan($server);

    expect($shell->scripts[0])->toContain("--after-cursor='s=old'")
        ->and($shell->scripts[0])->toContain("['/var/log/nginx/access.log']='1:500'")
        ->and($state->cursors['journal'])->toBe('s=old')
        ->and($state->cursors['files'])->toBe([]);

    $script = new ScanScript('@@M');
    expect($script->parse("\n@@M journal\n\n@@M journal-failed\n\n@@M end\n")->journalFailed)->toBeTrue();
});

test('a scan that cannot read the server keeps its cursors and shows why', function () {
    $server = Server::factory()->create();
    $state = tap(ScannerState::for($server))->update(['enabled' => true, 'cursors' => ['journal' => 's=old', 'files' => []]]);
    scannedServer(exitCode: 255);

    (new ScanServerLogs($state->fresh()))->handle(app(LogScanner::class));

    expect($state->fresh())
        ->last_error->toContain('exit code 255')
        ->cursors->journal->toBe('s=old');
});

test('the scan command queues a scan of every active server the scanner is on for', function () {
    Queue::fake();
    $on = Server::factory()->create();
    $off = Server::factory()->create();
    $provisioning = Server::factory()->create(['status' => ServerStatus::Provisioning]);
    ScannerState::for($on)->update(['enabled' => true]);
    ScannerState::for($off)->update(['enabled' => false]);
    ScannerState::for($provisioning)->update(['enabled' => true]);

    $this->artisan('security-scanner:scan')->assertSuccessful();

    Queue::assertPushed(ScanServerLogs::class, 1);
    Queue::assertPushed(ScanServerLogs::class, fn (ScanServerLogs $job) => $job->state->server_id === $on->id);
});

test('turning the scanner on queues the first scan', function () {
    Queue::fake();
    $server = Server::factory()->create();

    Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->set('enabled', true);

    expect(ScannerState::for($server)->enabled)->toBeTrue();
    Queue::assertPushed(ScanServerLogs::class);
});

test('addresses are blocked in the firewall, except the ones swage and its user connect from', function () {
    Queue::fake();
    $server = Server::factory()->create();
    ScannerState::for($server)->update(['panel_address' => '198.51.100.1']);

    $panel = Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->call('block', '198.51.100.1')
        ->assertHasErrors(['ip'])
        ->call('block', '127.0.0.1')
        ->assertHasErrors(['ip'])
        ->call('block', 'not-an-ip')
        ->assertHasErrors(['ip'])
        ->call('block', '203.0.113.9', 'Scanning')
        ->assertHasNoErrors();

    expect(BlockedAddress::sole())
        ->ip->toBe('203.0.113.9')
        ->reason->toBe('Scanning')
        ->status->toBe(ResourceStatus::Pending)
        ->blocked_by_id->toBe($server->user->id);

    $panel->call('block', '203.0.113.9')->assertHasErrors(['ip']);

    Queue::assertPushed(BlockAddress::class, 1);
});

test('blocking and unblocking run ufw on the server and are recorded in its activity', function () {
    $shell = fakeShell();
    $address = BlockedAddress::create(['server_id' => Server::factory()->create()->id, 'ip' => '203.0.113.9', 'status' => ResourceStatus::Pending]);

    app()->call([new BlockAddress($address), 'handle']);

    $shell->assertRan("ufw prepend deny from '203.0.113.9' comment 'Blocked by Swage security scanner'");
    $shell->assertRan("grep -qxF -- 'deny 203.0.113.9;' /etc/nginx/conf.d/swage-security-scanner-blocked.conf || echo 'deny 203.0.113.9;' >> /etc/nginx/conf.d/swage-security-scanner-blocked.conf");
    $shell->assertRan('systemctl reload nginx');
    expect($address->fresh()->status)->toBe(ResourceStatus::Installed)
        ->and($address->server->tasks()->first()->name)->toBe('Blocking 203.0.113.9 in the firewall and nginx');

    app()->call([new UnblockAddress($address), 'handle']);

    $shell->assertRan("ufw delete deny from '203.0.113.9'");
    $shell->assertRan("grep -vxF -- 'deny 203.0.113.9;' /etc/nginx/conf.d/swage-security-scanner-blocked.conf");
    expect(BlockedAddress::count())->toBe(0);
});

test('an alert about an address can block it, and alerts can be resolved', function () {
    Queue::fake();
    $server = Server::factory()->create();
    ScannerState::for($server)->update(['last_scanned_at' => now()]);
    $alert = SecurityAlert::create([
        'server_id' => $server->id, 'rule' => AlertRule::SshLoginAfterFailures, 'severity' => AlertSeverity::High, 'subject' => '203.0.113.9',
        'details' => ['user' => 'root', 'failed_attempts' => 40], 'first_seen_at' => now(), 'last_seen_at' => now(),
    ]);

    Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->assertSee('SSH login from an address that was failing to log in')
        ->assertSee('Logged in as root after 40 failed attempts from the same address.')
        ->call('blockFromAlert', $alert->id)
        ->call('resolve', $alert->id)
        ->assertSee('No open alerts.');

    expect(BlockedAddress::sole()->reason)->toBe('SSH login from an address that was failing to log in')
        ->and($alert->fresh()->resolved_by_id)->toBe($server->user->id);
});

test('fail2ban is installed with the server\'s ssh port', function () {
    $shell = fakeShell();
    $server = Server::factory()->create(['ssh_port' => 2222]);

    app()->call([new InstallFail2ban($server), 'handle']);

    $shell->assertRan('apt-get install -yq -o DPkg::Lock::Timeout=300 fail2ban');
    $shell->assertRan("[sshd]\nenabled = true\nport = 2222\nfindtime = 1h\n");
    $shell->assertRan("[recidive]\nenabled = true\nbackend = auto\nbantime = 1w");
    $shell->assertRan("[swage-probes]\nenabled = true\nport = http,https\nfilter = swage-probes\nlogpath = /var/log/nginx/*access.log\nbackend = auto\nfindtime = 1h\nmaxretry = 20\n");
    $shell->assertRan('prefregex = ^<HOST> \S+ \S+ \[\] "[A-Z]+ <F-CONTENT>[^ "]+</F-CONTENT>');
    $shell->assertRan("failregex = (?i:/\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|DS_Store|htpasswd|htaccess))\n            (?i:/wp-");
    $shell->assertRan('(?i:(\.\./|%%2e%%2e))');
    $shell->assertRan('ignoreip = 127.0.0.1/8 ::1 @SWAGE_PANEL_ADDRESS@ 173.245.48.0/20');
    $shell->assertRan("action = %(action_)s\n         swage-nginx-deny\n\n[recidive]\naction = %(action_)s\n         swage-nginx-deny");
    $shell->assertRan("cat > /etc/fail2ban/action.d/swage-nginx-deny.conf <<'CONF'\n[Definition]");
    $shell->assertRan("actionban = grep -qxF 'deny <ip>;' <file> || echo 'deny <ip>;' >> <file>\n            nginx -t -q && systemctl reload nginx");
    $shell->assertRan("actionunban = grep -vxF 'deny <ip>;' <file> > <file>.tmp; mv <file>.tmp <file>");
    $shell->assertRan('file = /etc/nginx/conf.d/swage-fail2ban-<name>.conf');
    expect(ScannerState::for($server))
        ->fail2ban_installed->toBeTrue()
        ->fail2ban_ignores_panel->toBeTrue()
        ->fail2ban_recidive_reads_log->toBeTrue()
        ->fail2ban_sshd_counts_hour->toBeTrue();
});

test('fail2ban never bans the address swage connects from', function () {
    $shell = fakeShell();
    $server = Server::factory()->create();
    ScannerState::for($server)->update(['panel_address' => '198.51.100.7']);

    app()->call([new InstallFail2ban($server), 'handle']);

    $script = $shell->lastScript();

    expect($script)
        ->toContain('panel_address=${SSH_CLIENT%% *}')
        ->toContain("[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 @SWAGE_PANEL_ADDRESS@ 198.51.100.7\n")
        ->toContain('ignoreip = 127.0.0.1/8 ::1 @SWAGE_PANEL_ADDRESS@ 198.51.100.7 173.245.48.0/20')
        ->toContain('sed -i "s/@SWAGE_PANEL_ADDRESS@/$panel_address/" /etc/fail2ban/jail.d/swage.conf')
        ->toContain('sed -i "s/@SWAGE_PANEL_ADDRESS@/$panel_address/" /etc/fail2ban/jail.d/swage-probes.conf')
        ->and(strpos($script, 'panel_address=${SSH_CLIENT'))->toBeLessThan(strpos($script, 'systemctl restart fail2ban'));
});

test('the scan script reads the probes jail\'s bans and reloads it when a new access log appears', function () {
    $script = (new ScanScript('@@M'))->render([]);

    expect($script)->toContain('for jail in sshd recidive swage-probes; do')
        ->and($script)->toContain('fail2ban-client reload swage-probes');
});

test('only people who manage the server can change the scanner, and others cannot see it', function () {
    $server = Server::factory()->create();

    Livewire::actingAs(User::factory()->create())->test(SecurityPanel::class, ['server' => $server])->assertForbidden();

    $admin = User::factory()->admin()->create();

    Livewire::actingAs($admin)->test(SecurityPanel::class, ['server' => $server])->assertOk()->set('enabled', true);
    Livewire::actingAs($admin)->test(SecurityPanel::class, ['server' => $server])->call('block', '203.0.113.9');

    expect(ScannerState::for($server)->enabled)->toBeFalse()
        ->and(BlockedAddress::count())->toBe(0);
});

test('old events and long resolved alerts are pruned', function () {
    $server = Server::factory()->create();
    $event = fn (string $bucket) => SecurityEvent::create(['server_id' => $server->id, 'kind' => EventKind::HttpProbe, 'ip' => '203.0.113.9', 'source' => 'nginx', 'bucket' => $bucket, 'count' => 1, 'first_seen_at' => $bucket, 'last_seen_at' => $bucket]);
    $event('2026-09-01 00:00:00');
    $kept = $event('2026-10-20 00:00:00');

    $this->artisan('model:prune', ['--model' => [SecurityEvent::class, SecurityAlert::class]])->assertSuccessful();

    expect(SecurityEvent::pluck('id')->all())->toBe([$kept->id]);
});

test('the busiest hostile addresses show when each was last seen, and blocked ones stay listed until they go quiet for a day', function () {
    $server = Server::factory()->create();
    ScannerState::for($server)->update(['last_scanned_at' => now()]);
    $event = fn (string $ip, string $kind, int $count, string $seen) => SecurityEvent::create(['server_id' => $server->id, 'kind' => $kind, 'ip' => $ip, 'source' => 'ssh', 'bucket' => now()->startOfHour(), 'count' => $count, 'first_seen_at' => $seen, 'last_seen_at' => $seen]);
    $event('203.0.113.9', EventKind::SshFailedLogin->value, 30, '2026-10-23 09:00:00');
    $event('203.0.113.9', EventKind::SshInvalidUser->value, 5, '2026-10-23 11:30:00');
    $event('203.0.113.10', EventKind::HttpProbe->value, 3, '2026-10-22 11:00:00');
    BlockedAddress::create(['server_id' => $server->id, 'ip' => '203.0.113.9', 'status' => ResourceStatus::Installed]);

    $addresses = Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->assertSee('Last seen')
        ->assertSee('30 minutes ago')
        ->get('addresses');

    expect($addresses)->toHaveCount(1)
        ->and($addresses[0])->toMatchArray(['ip' => '203.0.113.9', 'total' => 35, 'blocked' => true])
        ->and($addresses[0]['last_seen_at']->toDateTimeString())->toBe('2026-10-23 11:30:00');
});

test('each of the panel\'s tables shows ten rows a page', function () {
    $server = Server::factory()->create();
    $ips = collect(range(1, 12))->map(fn (int $i): string => "203.0.113.{$i}");
    ScannerState::for($server)->update(['last_scanned_at' => now(), 'fail2ban_installed' => true, 'fail2ban_banned' => collect(range(1, 12))->map(fn (int $i): string => "198.51.100.{$i}")->all()]);

    foreach ($ips as $i => $ip) {
        BlockedAddress::create(['server_id' => $server->id, 'ip' => "192.0.2.{$i}", 'status' => ResourceStatus::Installed]);
        SecurityAlert::create(['server_id' => $server->id, 'rule' => AlertRule::SshLoginNewAddress, 'severity' => AlertSeverity::Low, 'subject' => $ip, 'details' => ['user' => 'deploy'], 'first_seen_at' => now(), 'last_seen_at' => now()]);
        SecurityEvent::create(['server_id' => $server->id, 'kind' => EventKind::HttpProbe, 'ip' => $ip, 'source' => 'nginx', 'bucket' => now()->startOfHour(), 'count' => 100 - $i, 'first_seen_at' => now()->subMinutes(5), 'last_seen_at' => now()->subMinutes(5)]);
    }

    $panel = Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server]);

    foreach (['alerts' => 'alertsPage', 'addresses' => 'addressesPage', 'blockedAddresses' => 'blockedPage', 'bannedAddresses' => 'bannedPage'] as $table => $pageName) {
        expect($panel->get($table))->toHaveCount(10)->and($panel->get($table)->total())->toBe(12);

        $panel->call('setPage', 2, $pageName);

        expect($panel->get($table))->toHaveCount(2)->and($panel->get($table)->currentPage())->toBe(2);
    }

    expect($panel->get('addresses')->getCollection()->pluck('ip')->all())->toBe(['203.0.113.11', '203.0.113.12']);
});

test('the fail2ban panel says how many addresses are banned', function (array $banned, string $text) {
    $server = Server::factory()->create();
    ScannerState::for($server)->update(['fail2ban_installed' => true, 'fail2ban_banned' => $banned]);

    Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])->assertSee($text);
})->with([
    'none' => [[], 'Installed. No addresses are banned right now.'],
    'one' => [['203.0.113.9'], 'Installed. 1 address is banned right now.'],
    'several' => [['203.0.113.9', '203.0.113.10', '203.0.113.11'], 'Installed. 3 addresses are banned right now.'],
]);

test('addresses fail2ban has banned are listed under fail2ban instead of among the busiest', function () {
    $server = Server::factory()->create();
    ScannerState::for($server)->update(['last_scanned_at' => now(), 'fail2ban_installed' => true, 'fail2ban_banned' => ['203.0.113.9', '203.0.113.50']]);
    $event = fn (string $ip, int $count) => SecurityEvent::create(['server_id' => $server->id, 'kind' => EventKind::SshFailedLogin, 'ip' => $ip, 'source' => 'ssh', 'bucket' => now()->startOfHour(), 'count' => $count, 'first_seen_at' => now()->subMinutes(10), 'last_seen_at' => now()->subMinutes(10)]);
    $event('203.0.113.9', 40);
    $event('203.0.113.10', 6);

    $panel = Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->assertSee('Not in the last 24 hours');

    expect($panel->get('addresses')->getCollection()->pluck('ip')->all())->toBe(['203.0.113.10'])
        ->and($panel->get('bannedAddresses')->getCollection()->map(fn ($address) => [$address['ip'], $address['total']])->all())->toBe([
            ['203.0.113.9', 40],
            ['203.0.113.50', 0],
        ]);
});

test('cloudflare\'s own addresses are never counted, so they are never ranked or alerted on', function () {
    $server = Server::factory()->create();
    $probes = implode("\n", array_fill(0, 25, accessLine('104.16.1.1', 'GET /.env HTTP/1.1', 444)))."\n".accessLine('2606:4700::1111', 'GET /.git/config HTTP/1.1')."\n";

    scannedServer(files: ['/var/log/nginx/access.log' => ['inode' => 1, 'start' => 0, 'new' => true, 'content' => $probes]]);
    scan($server);

    expect(SecurityEvent::count())->toBe(0)
        ->and(SecurityAlert::count())->toBe(0);
});

test('addresses in cloudflare\'s ranges cannot be blocked, and addresses are stored in their shortest form', function () {
    Queue::fake();
    $server = Server::factory()->create();

    Livewire::actingAs($server->user)->test(SecurityPanel::class, ['server' => $server])
        ->call('block', '104.16.1.1')
        ->assertHasErrors(['ip'])
        ->assertSee('belongs to Cloudflare')
        ->call('block', '2606:4700::1111')
        ->assertHasErrors(['ip'])
        ->call('block', '2001:DB8:0:0::7')
        ->assertHasNoErrors();

    expect(BlockedAddress::pluck('ip')->all())->toBe(['2001:db8::7']);
});

test('scans block again any blocked address missing from nginx\'s deny list', function (?array $denied, int $restored) {
    Queue::fake();
    $server = Server::factory()->create();
    BlockedAddress::create(['server_id' => $server->id, 'ip' => '203.0.113.9', 'status' => ResourceStatus::Installed]);
    BlockedAddress::create(['server_id' => $server->id, 'ip' => '203.0.113.10', 'status' => ResourceStatus::Failed]);

    scannedServer(denied: $denied);
    scan($server);

    Queue::assertPushed(BlockAddress::class, $restored);
})->with([
    'missing from the list' => [[], 1],
    'already in the list' => [['203.0.113.9'], 0],
    'no nginx on the server' => [null, 0],
]);

test('the scan script reads nginx\'s deny list', function () {
    $script = new ScanScript('@@M');

    expect($script->render([]))->toContain("sed -n 's/^deny \\(.*\\);$/\\1/p' /etc/nginx/conf.d/swage-security-scanner-blocked.conf")
        ->and($script->parse("\n@@M nginx-deny\npresent\n203.0.113.9\nnonsense\n\n@@M end\n")->nginxDenied)->toBe(['203.0.113.9'])
        ->and($script->parse("\n@@M nginx-deny\n\n@@M end\n")->nginxDenied)->toBeNull();
});

test('cloudflare\'s ranges come from swage\'s own list', function () {
    expect(CloudflareAddresses::ranges())->toBe(CloudflareNetworks::RANGES)
        ->and(CloudflareAddresses::contains('104.16.1.1'))->toBeTrue()
        ->and(CloudflareAddresses::contains('203.0.113.9'))->toBeFalse();
});
