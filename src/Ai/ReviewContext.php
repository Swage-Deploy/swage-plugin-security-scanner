<?php

namespace Swage\SecurityScanner\Ai;

use Illuminate\Support\Collection;
use Swage\SecurityScanner\Enums\EventKind;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\IgnoredFinding;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;
use Swage\SecurityScanner\Models\TrustedAddress;

/**
 * What the AI review is given about a server: what the scanner recorded, read from Swage's database, and the
 * snapshot of how the server is set up.
 */
class ReviewContext
{
    /**
     * How many of the busiest hostile addresses are included.
     */
    public const int TOP_ADDRESSES = 25;

    /**
     * How many of each address's usernames or paths are included.
     */
    public const int TARGETS_PER_ADDRESS = 5;

    /**
     * @param  array<string, string>  $snapshot
     */
    public function prompt(ScannerState $state, array $snapshot): string
    {
        return static::wrap($this->encode($state, $snapshot));
    }

    /**
     * The data the review is given, as the JSON sent, which is stored with the review so people can see what it saw.
     *
     * @param  array<string, string>  $snapshot
     */
    public function encode(ScannerState $state, array $snapshot): string
    {
        return json_encode($this->build($state, $snapshot), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    }

    /**
     * The prompt for the given data.
     */
    public static function wrap(string $json): string
    {
        return "Review this server. The data is JSON.\n\n".$json;
    }

    /**
     * @param  array<string, string>  $snapshot
     * @return array<string, mixed>
     */
    public function build(ScannerState $state, array $snapshot): array
    {
        $serverId = $state->server_id;

        return [
            'reviewed_at' => now()->toIso8601String(),
            'ssh_password_guesses' => $this->passwordGuesses($snapshot),
            'scanner' => [
                'scanning_logs' => $state->enabled,
                'last_scanned_at' => $state->last_scanned_at?->toIso8601String(),
                'last_scan_error' => $state->last_error,
                'swage_connects_from' => $state->panel_address,
            ],
            'trusted_addresses' => TrustedAddress::query()->where('server_id', $serverId)->orderBy('ip')->get()
                ->map(fn (TrustedAddress $address): array => ['address' => $address->ip, 'note' => $address->note])->all(),
            'events_last_24_hours' => $this->totals($serverId),
            'events_per_day_last_7_days' => $this->daily($serverId),
            'busiest_hostile_addresses_last_24_hours' => $this->addresses($state),
            'open_alerts' => SecurityAlert::query()->where('server_id', $serverId)->open()->latest('last_seen_at')->limit(50)->get()
                ->map(fn (SecurityAlert $alert): array => [
                    'alert' => $alert->rule->title(),
                    'severity' => $alert->severity->value,
                    'address' => $alert->subject,
                    'summary' => $alert->summary(),
                    'occurrences' => $alert->occurrences,
                    'first_seen_at' => $alert->first_seen_at->toIso8601String(),
                    'last_seen_at' => $alert->last_seen_at->toIso8601String(),
                ])->all(),
            'blocked_addresses' => BlockedAddress::query()->where('server_id', $serverId)->latest()->limit(100)->get()
                ->map(fn (BlockedAddress $address): array => [
                    'address' => $address->ip,
                    'reason' => $address->reason,
                    'status' => $address->status->value,
                    'blocked_at' => $address->created_at?->toIso8601String(),
                ])->all(),
            'fail2ban' => [
                'installed' => $state->fail2ban_installed,
                'jails' => $state->fail2ban_jails,
                'banned_addresses' => $state->fail2ban_banned ?? [],
                'could_ban_swage' => $state->fail2banCanBanPanel(),
                'misses_repeat_offenders' => $state->fail2banMissesRepeatOffenders(),
                'misses_paced_ssh_guessing' => $state->fail2banMissesPacedSsh(),
                'misses_permanent_bans' => $state->fail2banBansTemporarily(),
                'misses_probes' => $state->fail2banMissesProbes(),
            ],
            'ignored_findings' => IgnoredFinding::query()->where('server_id', $serverId)->orderBy('key')->get()
                ->map(fn (IgnoredFinding $finding): array => ['key' => $finding->key, 'title' => $finding->title])->all(),
            'snapshot' => collect(PostureScript::SECTIONS)
                ->mapWithKeys(fn (string $label, string $section): array => [$label => $snapshot[$section] ?? null])
                ->all(),
        ];
    }

    /**
     * Whether a failed SSH password guess could ever succeed, worked out from the snapshot rather than left to the
     * model, which tends to rate guessing as serious even when nothing it guesses can work.
     *
     * @param  array<string, string>  $snapshot
     * @return array<string, mixed>
     */
    protected function passwordGuesses(array $snapshot): array
    {
        $readable = fn (string $section): bool => ! in_array(trim($snapshot[$section] ?? ''), ['', 'unavailable'], true);

        if (! $readable('sshd') || ! $readable('accounts') || ! $readable('passwords')) {
            return ['can_succeed' => null, 'accounts_open_to_guessing' => [], 'why' => 'The SSH settings, accounts or passwords could not be read.'];
        }

        $settings = collect(explode("\n", $snapshot['sshd']))
            ->map(fn (string $line): array => preg_split('/\s+/', strtolower(trim($line)), 2) + [1 => ''])
            ->mapWithKeys(fn (array $setting): array => [$setting[0] => trim($setting[1])]);

        $methods = $settings->get('authenticationmethods', 'any');

        // A guess alone only gets in when one of the allowed ways of logging in needs nothing but a password.
        $passwordsAccepted = ($settings->get('passwordauthentication') === 'yes' || $settings->get('kbdinteractiveauthentication') === 'yes')
            && ($methods === 'any' || collect(preg_split('/\s+/', $methods))->contains(
                fn (string $list): bool => collect(explode(',', $list))->every(fn (string $method): bool => in_array(strtok($method, ':'), ['password', 'keyboard-interactive'], true)),
            ));

        if (! $passwordsAccepted) {
            return ['can_succeed' => false, 'accounts_open_to_guessing' => [], 'why' => 'SSH does not accept password logins.'];
        }

        $canLogIn = collect(explode("\n", $snapshot['accounts']))->map(fn (string $line): string => strtok(trim($line), ' ') ?: '')->filter()->all();

        $open = collect(explode("\n", $snapshot['passwords']))
            ->map(fn (string $line): array => explode(' ', trim($line), 2) + [1 => ''])
            ->filter(fn (array $account): bool => in_array($account[0], $canLogIn, true)
                && ($account[1] === 'password set' || ($account[1] === 'empty password' && $settings->get('permitemptypasswords') === 'yes'))
                && ($account[0] !== 'root' || $settings->get('permitrootlogin') === 'yes'))
            ->map(fn (array $account): string => $account[0])
            ->values()
            ->all();

        return $open === []
            ? ['can_succeed' => false, 'accounts_open_to_guessing' => [], 'why' => 'SSH accepts passwords, but no account that may log in with one has a usable password.']
            : ['can_succeed' => true, 'accounts_open_to_guessing' => $open, 'why' => 'SSH accepts passwords, and these accounts can log in with one.'];
    }

    /**
     * @return array<string, int>
     */
    protected function totals(int $serverId): array
    {
        return SecurityEvent::query()
            ->where('server_id', $serverId)
            ->where('last_seen_at', '>=', now()->subDay())
            ->selectRaw('kind, sum(count) as total')
            ->groupBy('kind')
            ->get()
            ->mapWithKeys(fn (SecurityEvent $row): array => [$row->kind->label() => (int) $row->total])
            ->all();
    }

    /**
     * @return array<string, array<string, int>>
     */
    protected function daily(int $serverId): array
    {
        return SecurityEvent::query()
            ->where('server_id', $serverId)
            ->where('bucket', '>=', now()->subDays(7)->startOfDay())
            ->selectRaw('kind, bucket, sum(count) as total')
            ->groupBy('kind', 'bucket')
            ->get()
            ->groupBy(fn (SecurityEvent $row): string => $row->bucket->toDateString())
            ->sortKeys()
            ->map(fn (Collection $rows): array => $rows->groupBy(fn (SecurityEvent $row): string => $row->kind->label())
                ->map(fn (Collection $kind): int => (int) $kind->sum('total'))
                ->all())
            ->all();
    }

    /**
     * @return list<array<string, mixed>>
     */
    protected function addresses(ScannerState $state): array
    {
        $hostile = fn () => SecurityEvent::query()
            ->where('server_id', $state->server_id)
            ->whereNotNull('ip')
            ->whereIn('kind', EventKind::hostile())
            ->where('last_seen_at', '>=', now()->subDay());

        $top = $hostile()
            ->selectRaw('ip, sum(count) as total, min(first_seen_at) as first_seen_at, max(last_seen_at) as last_seen_at')
            ->groupBy('ip')
            ->orderByDesc('total')
            ->orderBy('ip')
            ->limit(self::TOP_ADDRESSES)
            ->get();

        $rows = $hostile()->whereIn('ip', $top->pluck('ip'))->get(['ip', 'kind', 'count', 'targets'])->groupBy('ip');
        $banned = $state->fail2ban_banned ?? [];
        $blocked = BlockedAddress::query()->where('server_id', $state->server_id)->pluck('ip')->all();

        return $top->map(fn (SecurityEvent $address): array => [
            'address' => $address->ip,
            'events' => (int) $address->total,
            'kinds' => $rows->get($address->ip, collect())->groupBy(fn (SecurityEvent $row): string => $row->kind->label())->map->sum('count')->all(),
            'targets' => $rows->get($address->ip, collect())->flatMap(fn (SecurityEvent $row): array => $row->targets ?? [])->unique()->take(self::TARGETS_PER_ADDRESS)
                ->map(fn (mixed $target): string => mb_strimwidth((string) $target, 0, 120, '…'))->values()->all(),
            'first_seen_at' => $address->first_seen_at?->toIso8601String(),
            'last_seen_at' => $address->last_seen_at?->toIso8601String(),
            'banned_by_fail2ban' => in_array($address->ip, $banned, true),
            'blocked' => in_array($address->ip, $blocked, true),
        ])->values()->all();
    }
}
