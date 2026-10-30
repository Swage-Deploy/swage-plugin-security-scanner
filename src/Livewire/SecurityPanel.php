<?php

namespace Swage\SecurityScanner\Livewire;

use App\Enums\ResourceStatus;
use App\Models\Server;
use Carbon\CarbonInterface;
use Flux\Flux;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Collection as SupportCollection;
use Illuminate\Validation\ValidationException;
use Livewire\Attributes\Computed;
use Livewire\Attributes\Locked;
use Livewire\Component;
use Livewire\WithPagination;
use Swage\SecurityScanner\Ai\AiSettings;
use Swage\SecurityScanner\CloudflareAddresses;
use Swage\SecurityScanner\Enums\AlertSeverity;
use Swage\SecurityScanner\Enums\EventKind;
use Swage\SecurityScanner\Jobs\BlockAddress;
use Swage\SecurityScanner\Jobs\InstallFail2ban;
use Swage\SecurityScanner\Jobs\ReviewServerSecurity;
use Swage\SecurityScanner\Jobs\ScanServerLogs;
use Swage\SecurityScanner\Jobs\UnbanAllFail2ban;
use Swage\SecurityScanner\Jobs\UnblockAddress;
use Swage\SecurityScanner\Jobs\UpdateFail2banTrustedAddresses;
use Swage\SecurityScanner\Models\AiReview;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\Fail2banBan;
use Swage\SecurityScanner\Models\IgnoredFinding;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;
use Swage\SecurityScanner\Models\TrustedAddress;

/**
 * The security scanner's panel on a server's Plugins tab: whether scanning is on, open SSH login alerts, the busiest
 * hostile addresses of the last day, the addresses blocked in the firewall, trusted addresses, fail2ban, and the AI
 * review.
 */
class SecurityPanel extends Component
{
    use WithPagination;

    /**
     * How many rows each of the panel's tables shows at a time.
     */
    public const int PER_PAGE = 10;

    public Server $server;

    public bool $enabled = false;

    public bool $aiEnabled = false;

    /**
     * The data the latest AI review was sent, while it is being viewed.
     */
    #[Locked]
    public ?string $reviewInput = null;

    public string $ip = '';

    public string $reason = '';

    public string $trustIp = '';

    public string $trustNote = '';

    public function mount(): void
    {
        $this->authorize('view', $this->server);

        $this->enabled = $this->state->enabled;
        $this->aiEnabled = $this->state->ai_enabled;
    }

    #[Computed]
    public function state(): ScannerState
    {
        return ScannerState::for($this->server);
    }

    public function updatedEnabled(): void
    {
        $this->authorize('update', $this->server);

        $this->state->update(['enabled' => $this->enabled]);

        if ($this->enabled) {
            ScanServerLogs::dispatch($this->state);
        }

        Flux::toast(variant: 'success', text: $this->enabled
            ? __('Scanning this server\'s logs. The first scan reads the last few minutes of SSH logins and the end of each access log.')
            : __('Stopped scanning this server\'s logs.'));
    }

    /**
     * Turn the AI review on or off for the server. Turning it on reviews the server straight away.
     *
     * @throws ValidationException
     */
    public function updatedAiEnabled(): void
    {
        $this->authorize('update', $this->server);

        if ($this->aiEnabled && ! $this->ai->isConfigured()) {
            $this->aiEnabled = false;

            throw ValidationException::withMessages(['aiEnabled' => __('An administrator needs to set the AI review\'s API URL and model first.')]);
        }

        $this->state->update(['ai_enabled' => $this->aiEnabled]);

        if ($this->aiEnabled) {
            ReviewServerSecurity::dispatch($this->state, auth()->user());
        }

        Flux::toast(variant: 'success', text: $this->aiEnabled
            ? __('Reviewing this server with AI. The first review shows here in a minute or two.')
            : __('Stopped reviewing this server with AI. Earlier reviews are kept.'));
    }

    public function review(): void
    {
        $this->authorize('update', $this->server);

        abort_unless($this->state->ai_enabled && $this->ai->isConfigured(), 403);

        ReviewServerSecurity::dispatch($this->state, auth()->user());

        Flux::toast(variant: 'success', text: __('Reviewing this server with AI.'));
    }

    #[Computed]
    public function ai(): AiSettings
    {
        return app(AiSettings::class);
    }

    /**
     * The latest AI review, without the data it was sent, which is only loaded when someone asks to see it.
     */
    #[Computed]
    public function latestReview(): ?AiReview
    {
        return AiReview::query()->where('server_id', $this->server->id)->latest()->latest('id')
            ->first(['id', 'server_id', 'model', 'reported_model', 'summary', 'findings', 'checked', 'missing_sections', 'input_tokens', 'output_tokens', 'requested_by_id', 'created_at']);
    }

    /**
     * Show the data the latest review was sent. It includes the server's accounts and sudo rules, so only people who
     * can manage the server see it.
     */
    public function showReviewInput(): void
    {
        $this->authorize('update', $this->server);

        $this->reviewInput = $this->latestReview
            ? (string) AiReview::query()->whereKey($this->latestReview->id)->value('input')
            : null;

        Flux::modal('security-scanner-review-input')->show();
    }

    /**
     * The findings people have ignored on the server, newest first.
     *
     * @return Collection<int, IgnoredFinding>
     */
    #[Computed]
    public function ignoredFindings(): Collection
    {
        return IgnoredFinding::query()->where('server_id', $this->server->id)->with('ignoredBy')->latest()->latest('id')->get();
    }

    /**
     * Ignore one of the latest review's findings. Later reviews still check for it, and it shows under Ignored.
     */
    public function ignoreFinding(string $key): void
    {
        $this->authorize('update', $this->server);

        $finding = collect($this->latestReview?->sortedFindings() ?? [])->firstWhere('key', $key);

        abort_if($finding === null, 404);

        IgnoredFinding::firstOrCreate(
            ['server_id' => $this->server->id, 'key' => $key],
            ['title' => mb_strimwidth($finding['title'], 0, 255, '…'), 'ignored_by_id' => auth()->id()],
        );

        unset($this->ignoredFindings);

        Flux::toast(variant: 'success', text: __('Ignoring ":title". Reviews still check for it, and it shows under Ignored.', ['title' => $finding['title']]));
    }

    public function stopIgnoring(int $ignoredId): void
    {
        $this->authorize('update', $this->server);

        IgnoredFinding::query()->where('server_id', $this->server->id)->findOrFail($ignoredId)->delete();

        unset($this->ignoredFindings);
    }

    public function scan(): void
    {
        $this->authorize('update', $this->server);

        ScanServerLogs::dispatch($this->state);

        Flux::toast(variant: 'success', text: __('Scanning the server\'s logs.'));
    }

    public function resolve(int $alertId): void
    {
        $this->authorize('update', $this->server);

        SecurityAlert::query()->where('server_id', $this->server->id)->open()->findOrFail($alertId)->resolve(auth()->user());
    }

    public function resolveAll(): void
    {
        $this->authorize('update', $this->server);

        SecurityAlert::query()->where('server_id', $this->server->id)->open()->update([
            'resolved_at' => now(),
            'resolved_by_id' => auth()->id(),
        ]);

        $this->resetPage('alertsPage');
    }

    /**
     * Block an address in the server's firewall, from an alert, the busiest addresses or the block form.
     *
     * @throws ValidationException
     */
    public function block(?string $ip = null, ?string $reason = null): void
    {
        $this->authorize('update', $this->server);

        if ($ip !== null) {
            $this->ip = $ip;
            $this->reason = (string) $reason;
        }

        $validated = $this->validate([
            'ip' => ['required', 'ip'],
            'reason' => ['nullable', 'string', 'max:255'],
        ]);

        $validated['ip'] = (string) inet_ntop((string) inet_pton($validated['ip']));

        if (CloudflareAddresses::contains($validated['ip'])) {
            throw ValidationException::withMessages(['ip' => __(':ip belongs to Cloudflare, whose proxy connects to sites on its visitors\' behalf. Blocking it would cut off every visitor Cloudflare routes through it.', ['ip' => $validated['ip']])]);
        }

        if ($validated['ip'] === $this->state->panel_address) {
            throw ValidationException::withMessages(['ip' => __('Swage connects to this server from :ip, so blocking it would lock Swage out.', ['ip' => $validated['ip']])]);
        }

        if ($validated['ip'] === request()->ip()) {
            throw ValidationException::withMessages(['ip' => __('This is the address you are using Swage from.')]);
        }

        if (TrustedAddress::covers(TrustedAddress::rangesFor($this->server->id), $validated['ip'])) {
            throw ValidationException::withMessages(['ip' => __(':ip is trusted on this server. Stop trusting it first.', ['ip' => $validated['ip']])]);
        }

        $address = BlockedAddress::firstOrNew(['server_id' => $this->server->id, 'ip' => $validated['ip']]);

        if ($address->exists && $address->status !== ResourceStatus::Failed) {
            throw ValidationException::withMessages(['ip' => __(':ip is already blocked.', ['ip' => $validated['ip']])]);
        }

        $address->fill([
            'reason' => filled($validated['reason']) ? $validated['reason'] : null,
            'status' => ResourceStatus::Pending,
            'blocked_by_id' => auth()->id(),
        ])->save();

        BlockAddress::dispatch($address);

        $this->reset('ip', 'reason');
        Flux::modal('security-scanner-block')->close();
        Flux::toast(variant: 'success', text: __('Blocking :ip in the firewall and nginx.', ['ip' => $address->ip]));
    }

    /**
     * Block the address an alert is about, giving the alert as the reason.
     *
     * @throws ValidationException
     */
    public function blockFromAlert(int $alertId): void
    {
        $alert = SecurityAlert::query()->where('server_id', $this->server->id)->findOrFail($alertId);

        $this->block($alert->subject, $alert->rule->title());
    }

    public function unblock(int $addressId): void
    {
        $this->authorize('update', $this->server);

        $address = BlockedAddress::query()->where('server_id', $this->server->id)->findOrFail($addressId);
        $address->update(['status' => ResourceStatus::Removing]);

        UnblockAddress::dispatch($address);
    }

    /**
     * Trust an address or range on the server, from an alert or the trust form. What the scanner recorded about it is
     * cleared, its open alerts are resolved, it is unblocked, and fail2ban stops banning it.
     *
     * @throws ValidationException
     */
    public function trust(?string $ip = null, ?string $note = null): void
    {
        $this->authorize('update', $this->server);

        if ($ip !== null) {
            $this->trustIp = $ip;
            $this->trustNote = (string) $note;
        }

        $validated = $this->validate([
            'trustIp' => ['required', 'string', 'max:64'],
            'trustNote' => ['nullable', 'string', 'max:255'],
        ]);

        $range = TrustedAddress::normalize($validated['trustIp']);

        if ($range === null) {
            throw ValidationException::withMessages(['trustIp' => __('Enter an address, such as 203.0.113.7, or a range no wider than /:ipv4 for IPv4 or /:ipv6 for IPv6, such as 203.0.113.0/24.', ['ipv4' => TrustedAddress::MIN_IPV4_PREFIX, 'ipv6' => TrustedAddress::MIN_IPV6_PREFIX])]);
        }

        $address = TrustedAddress::firstOrNew(['server_id' => $this->server->id, 'ip' => $range]);

        if ($address->exists) {
            throw ValidationException::withMessages(['trustIp' => __(':ip is already trusted.', ['ip' => $range])]);
        }

        $address->fill(['note' => filled($validated['trustNote']) ? $validated['trustNote'] : null, 'trusted_by_id' => auth()->id()])->save();

        $this->forget([$range]);

        UpdateFail2banTrustedAddresses::dispatch($this->server);

        $this->reset('trustIp', 'trustNote');
        unset($this->trustedAddresses, $this->blocked);
        Flux::modal('security-scanner-trust')->close();
        Flux::toast(variant: 'success', text: __('Trusting :ip. It won\'t be counted, alerted on, blocked or banned.', ['ip' => $range]));
    }

    /**
     * Trust the address an alert is about, such as one of your own logins.
     *
     * @throws ValidationException
     */
    public function trustFromAlert(int $alertId): void
    {
        $alert = SecurityAlert::query()->where('server_id', $this->server->id)->findOrFail($alertId);

        $this->trust($alert->subject, $alert->rule->title());
    }

    public function untrust(int $addressId): void
    {
        $this->authorize('update', $this->server);

        TrustedAddress::query()->where('server_id', $this->server->id)->where('swage_host', false)->findOrFail($addressId)->delete();

        UpdateFail2banTrustedAddresses::dispatch($this->server);

        unset($this->trustedAddresses);
    }

    /**
     * Clear what the scanner recorded about the given ranges, resolve their open alerts and unblock them.
     *
     * @param  list<string>  $ranges
     */
    protected function forget(array $ranges): void
    {
        $covered = fn (?string $ip): bool => TrustedAddress::covers($ranges, $ip);

        $ips = SecurityEvent::query()->where('server_id', $this->server->id)->whereNotNull('ip')->distinct()->pluck('ip')->filter($covered);
        SecurityEvent::query()->where('server_id', $this->server->id)->whereIn('ip', $ips)->delete();

        SecurityAlert::query()->where('server_id', $this->server->id)->open()->get()
            ->filter(fn (SecurityAlert $alert): bool => $covered($alert->subject))
            ->each(fn (SecurityAlert $alert) => $alert->resolve(auth()->user()));

        BlockedAddress::query()->where('server_id', $this->server->id)->where('status', '!=', ResourceStatus::Removing)->get()
            ->filter(fn (BlockedAddress $address): bool => $covered($address->ip))
            ->each(function (BlockedAddress $address) {
                $address->update(['status' => ResourceStatus::Removing]);
                UnblockAddress::dispatch($address);
            });
    }

    /**
     * @return Collection<int, TrustedAddress>
     */
    #[Computed]
    public function trustedAddresses(): Collection
    {
        return TrustedAddress::query()->where('server_id', $this->server->id)->with('trustedBy')->orderBy('ip')->get();
    }

    public function installFail2ban(): void
    {
        $this->authorize('update', $this->server);

        InstallFail2ban::dispatch($this->server);

        Flux::toast(variant: 'success', text: $this->state->fail2ban_installed
            ? __('Updating fail2ban\'s jails.')
            : __('Installing fail2ban. It shows as installed after the next scan.'));
    }

    public function unbanAll(): void
    {
        $this->authorize('update', $this->server);

        UnbanAllFail2ban::dispatch($this->server);

        Flux::toast(variant: 'success', text: __('Lifting every fail2ban ban.'));
    }

    /**
     * The open alerts, most severe first, leaving out addresses fail2ban has banned or that are blocked, which can't
     * reach the server.
     *
     * @return LengthAwarePaginator<int, SecurityAlert>
     */
    #[Computed]
    public function alerts(): LengthAwarePaginator
    {
        $blocked = $this->blocked->where('status', ResourceStatus::Installed)->pluck('ip')->all();

        $severity = collect(AlertSeverity::cases())->map(fn (AlertSeverity $severity): string => "when '{$severity->value}' then {$severity->rank()}")->implode(' ');

        return SecurityAlert::query()
            ->where('server_id', $this->server->id)
            ->open()
            ->whereNotIn('subject', $this->bans()->select('ip'))
            ->whereNotIn('subject', $blocked)
            ->orderByRaw("case severity {$severity} else 0 end desc")
            ->latest('last_seen_at')
            ->paginate(self::PER_PAGE, pageName: 'alertsPage');
    }

    /**
     * How many of each kind of event the last day held.
     *
     * @return array<string, int>
     */
    #[Computed]
    public function totals(): array
    {
        return SecurityEvent::query()
            ->where('server_id', $this->server->id)
            ->where('last_seen_at', '>=', now()->subDay())
            ->selectRaw('kind, sum(count) as total')
            ->groupBy('kind')
            ->pluck('total', 'kind')
            ->map(fn (mixed $total): int => (int) $total)
            ->all();
    }

    /**
     * The addresses with the most hostile events in the last day, leaving out those fail2ban has banned, which are
     * listed in the fail2ban panel instead.
     *
     * @return LengthAwarePaginator<int, array{ip: string, total: int, kinds: array<string, int>, last_seen_at: CarbonInterface|null, blocked: bool}>
     */
    #[Computed]
    public function addresses(): LengthAwarePaginator
    {
        $page = $this->hostileEvents()
            ->whereNotIn('ip', $this->bans()->select('ip'))
            ->selectRaw('ip, sum(count) as total, max(last_seen_at) as last_seen_at')
            ->groupBy('ip')
            ->orderByDesc('total')
            ->orderBy('ip')
            ->paginate(self::PER_PAGE, pageName: 'addressesPage');

        return $page->setCollection($this->describe($page->getCollection()));
    }

    /**
     * The addresses fail2ban has banned, with what they did in the last day, busiest first. Bans are permanent, so
     * most banned addresses have nothing recorded in the last day: they follow, newest ban first.
     *
     * @return LengthAwarePaginator<int, array{ip: string, total: int, kinds: array<string, int>, last_seen_at: CarbonInterface|null, blocked: bool}>
     */
    #[Computed]
    public function bannedAddresses(): LengthAwarePaginator
    {
        $events = $this->hostileEvents()
            ->selectRaw('ip, sum(count) as total, max(last_seen_at) as last_seen_at')
            ->groupBy('ip');

        $page = $this->bans()
            ->leftJoinSub($events, 'events', 'events.ip', '=', 'security_scanner_fail2ban_bans.ip')
            ->select('security_scanner_fail2ban_bans.ip', 'events.total', 'events.last_seen_at')
            ->orderByRaw('case when events.total is null then 1 else 0 end')
            ->orderByDesc('events.total')
            ->latest('security_scanner_fail2ban_bans.id')
            ->paginate(self::PER_PAGE, pageName: 'bannedPage');

        return $page->setCollection($this->describe(
            $page->getCollection()->map(fn (Fail2banBan $ban): SecurityEvent => (new SecurityEvent)->forceFill(['ip' => $ban->ip, 'total' => $ban->total, 'last_seen_at' => $ban->last_seen_at]))
        ));
    }

    /**
     * How many addresses fail2ban has banned on the server.
     */
    #[Computed]
    public function bannedCount(): int
    {
        return $this->bans()->count();
    }

    /**
     * @return Builder<Fail2banBan>
     */
    protected function bans(): Builder
    {
        return Fail2banBan::query()->where('security_scanner_fail2ban_bans.server_id', $this->server->id);
    }

    /**
     * @return Builder<SecurityEvent>
     */
    protected function hostileEvents(): Builder
    {
        return SecurityEvent::query()
            ->where('server_id', $this->server->id)
            ->whereNotNull('ip')
            ->whereIn('kind', EventKind::hostile())
            ->where('last_seen_at', '>=', now()->subDay());
    }

    /**
     * Say what each address's hostile events in the last day were, and whether it is blocked.
     *
     * @param  SupportCollection<int, SecurityEvent>  $rows
     * @return SupportCollection<int, array{ip: string, total: int, kinds: array<string, int>, last_seen_at: CarbonInterface|null, blocked: bool}>
     */
    protected function describe(SupportCollection $rows): SupportCollection
    {
        $kinds = $this->hostileEvents()->whereIn('ip', $rows->pluck('ip'))->selectRaw('ip, kind, sum(count) as total')->groupBy('ip', 'kind')->get()->groupBy('ip');
        $blocked = $this->blocked->pluck('ip');

        return $rows->map(fn (SecurityEvent $row): array => [
            'ip' => $row->ip,
            'total' => (int) $row->total,
            'kinds' => $kinds->get($row->ip, collect())->mapWithKeys(fn (SecurityEvent $kind): array => [$kind->kind->label() => (int) $kind->total])->sortDesc()->all(),
            'last_seen_at' => $row->last_seen_at,
            'blocked' => $blocked->contains($row->ip),
        ])->values();
    }

    /**
     * Every address blocked on the server, for marking addresses as blocked elsewhere in the panel.
     *
     * @return Collection<int, BlockedAddress>
     */
    #[Computed]
    public function blocked(): Collection
    {
        return BlockedAddress::query()->where('server_id', $this->server->id)->get(['id', 'ip', 'status']);
    }

    /**
     * @return LengthAwarePaginator<int, BlockedAddress>
     */
    #[Computed]
    public function blockedAddresses(): LengthAwarePaginator
    {
        return BlockedAddress::query()
            ->where('server_id', $this->server->id)
            ->with('blockedBy')
            ->latest()
            ->latest('id')
            ->paginate(self::PER_PAGE, pageName: 'blockedPage');
    }

    public function render(): View
    {
        return view('security-scanner::panel');
    }
}
