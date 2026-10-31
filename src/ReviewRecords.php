<?php

namespace Swage\SecurityScanner;

use App\Models\Server;
use Illuminate\Support\Collection;
use Swage\SecurityScanner\Enums\EventKind;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\Fail2banBan;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;
use Swage\SecurityScanner\Models\TrustedAddress;

/**
 * What the scanner recorded about a server, for the AI review plugin (swage/ai-review) to send with its reviews, and
 * what the review needs to know to read it. The AI review finds this class by name, so keep its name and the
 * signatures of for() and instructions().
 */
class ReviewRecords
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
     * The scanner's records of the server, or null when it doesn't scan the server.
     *
     * @return array<string, mixed>|null
     */
    public function for(Server $server): ?array
    {
        $state = ScannerState::query()->where('server_id', $server->id)->first();

        if ($state === null || ! $state->enabled) {
            return null;
        }

        return [
            'last_scanned_at' => $state->last_scanned_at?->toIso8601String(),
            'last_scan_error' => $state->last_error,
            'swage_connects_from' => $state->panel_address,
            'trusted_addresses' => TrustedAddress::query()->where('server_id', $server->id)->orderBy('ip')->get()
                ->map(fn (TrustedAddress $address): array => ['address' => $address->ip, 'note' => $address->swage_host ? 'Swage Host' : $address->note])->all(),
            'events_last_24_hours' => $this->totals($server->id),
            'events_per_day_last_7_days' => $this->daily($server->id),
            'busiest_hostile_addresses_last_24_hours' => $this->addresses($server->id),
            'open_alerts' => SecurityAlert::query()->where('server_id', $server->id)->open()->latest('last_seen_at')->limit(50)->get()
                ->map(fn (SecurityAlert $alert): array => [
                    'alert' => $alert->rule->title(),
                    'severity' => $alert->severity->value,
                    'address' => $alert->subject,
                    'summary' => $alert->summary(),
                    'occurrences' => $alert->occurrences,
                    'first_seen_at' => $alert->first_seen_at->toIso8601String(),
                    'last_seen_at' => $alert->last_seen_at->toIso8601String(),
                ])->all(),
            'blocked_addresses' => BlockedAddress::query()->where('server_id', $server->id)->latest()->limit(100)->get()
                ->map(fn (BlockedAddress $address): array => [
                    'address' => $address->ip,
                    'reason' => $address->reason,
                    'status' => $address->status->value,
                    'blocked_at' => $address->created_at?->toIso8601String(),
                ])->all(),
            'fail2ban' => [
                'installed' => $state->fail2ban_installed,
                'jails' => $state->fail2ban_jails,
                'banned_count' => Fail2banBan::query()->where('server_id', $server->id)->count(),
                'could_ban_swage' => $state->fail2banCanBanPanel(),
                'misses_repeat_offenders' => $state->fail2banMissesRepeatOffenders(),
                'misses_paced_ssh_guessing' => $state->fail2banMissesPacedSsh(),
                'misses_permanent_bans' => $state->fail2banBansTemporarily(),
                'misses_probes' => $state->fail2banMissesProbes(),
            ],
        ];
    }

    /**
     * What the review is told about reading the records, which go under security_scanner in what it is sent.
     */
    public function instructions(): string
    {
        return <<<'TEXT'
        security_scanner holds what the scanner recorded: SSH and sudo failures, probes for vulnerable files and login
        submissions per address per hour, its alerts about SSH logins, the addresses blocked in ufw and nginx, and
        fail2ban's state. Swage's own SSH logins are not counted, and Cloudflare's addresses are never counted or
        blocked. Don't report something as a problem when the data shows it is handled, such as addresses fail2ban has
        banned or that are blocked.

        People trust the addresses and ranges under trusted_addresses, such as their office's. The scanner doesn't count
        them and fail2ban never bans them, by choice. Don't report anything about them, such as their logins under recent
        logins, and don't suggest blocking or banning them.

        Only events counted as "SSH logins" are logins that succeeded. Every other SSH count is a failed attempt, and the
        usernames under an address's targets are the names it tried, which need not exist: they don't show accounts on
        the server. The snapshot's accounts sections are what exists.

        Hostile addresses that are neither banned nor blocked are normal. Most are scanners that come and go, fail2ban
        only bans an address once it passes its jail's limit in a day, and then bans it for good unless
        misses_permanent_bans is true, and banned_by_fail2ban only says whether it was banned at the last scan. People
        are not expected to block addresses by hand to keep up, so don't report that the blocked list is short, and
        don't suggest blocking addresses fail2ban can deal with. Only report hostile addresses when fail2ban is missing
        or not keeping up, as its misses_ fields say, when one address attacks far harder than the rest without being
        banned, or when one did more than fail, such as logging in. When fail2ban is missing, suggest installing it from
        the server's Security scanner tab, and when a misses_ field is true, suggest updating it there.

        Many addresses each making a few SSH guesses is a spread-out attack that fail2ban's per-address limits are not
        meant to catch. Don't suggest lowering fail2ban's limits for it, which would ban real people who mistype.

        Whatever ssh_password_guesses says, a large volume of failed SSH attempts, or of probes for vulnerable files such
        as .env and .git, is not a finding on its own while fail2ban is running and none of its misses_ fields are true:
        that is fail2ban doing its job, and every public server sees it. Don't report the volume, or call it exposure.
        TEXT;
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
    protected function addresses(int $serverId): array
    {
        $hostile = fn () => SecurityEvent::query()
            ->where('server_id', $serverId)
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
        $banned = Fail2banBan::query()->where('server_id', $serverId)->whereIn('ip', $top->pluck('ip'))->pluck('ip')->all();
        $blocked = BlockedAddress::query()->where('server_id', $serverId)->pluck('ip')->all();

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
