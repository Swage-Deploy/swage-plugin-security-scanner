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
use Illuminate\Pagination\Paginator;
use Illuminate\Support\Collection as SupportCollection;
use Illuminate\Validation\ValidationException;
use Livewire\Attributes\Computed;
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
use Swage\SecurityScanner\Jobs\UnblockAddress;
use Swage\SecurityScanner\Models\AiReview;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;

/**
 * The security scanner's panel on a server's Plugins tab: whether scanning is on, open SSH login alerts, the busiest
 * hostile addresses of the last day, the addresses blocked in the firewall, fail2ban, and the AI review.
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

    public string $ip = '';

    public string $reason = '';

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

    #[Computed]
    public function latestReview(): ?AiReview
    {
        return AiReview::query()->where('server_id', $this->server->id)->latest()->latest('id')->first();
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

    public function installFail2ban(): void
    {
        $this->authorize('update', $this->server);

        InstallFail2ban::dispatch($this->server);

        Flux::toast(variant: 'success', text: $this->state->fail2ban_installed
            ? __('Updating fail2ban\'s jails.')
            : __('Installing fail2ban. It shows as installed after the next scan.'));
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
        $banned = [
            ...$this->state->fail2ban_banned ?? [],
            ...$this->blocked->where('status', ResourceStatus::Installed)->pluck('ip'),
        ];

        $severity = collect(AlertSeverity::cases())->map(fn (AlertSeverity $severity): string => "when '{$severity->value}' then {$severity->rank()}")->implode(' ');

        return SecurityAlert::query()
            ->where('server_id', $this->server->id)
            ->open()
            ->whereNotIn('subject', $banned)
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
            ->whereNotIn('ip', $this->state->fail2ban_banned ?? [])
            ->selectRaw('ip, sum(count) as total, max(last_seen_at) as last_seen_at')
            ->groupBy('ip')
            ->orderByDesc('total')
            ->orderBy('ip')
            ->paginate(self::PER_PAGE, pageName: 'addressesPage');

        return $page->setCollection($this->describe($page->getCollection()));
    }

    /**
     * The addresses fail2ban has banned, with what they did in the last day, busiest first. An address banned for
     * longer, such as by the week long recidive jail, may have nothing recorded in the last day.
     *
     * @return LengthAwarePaginator<int, array{ip: string, total: int, kinds: array<string, int>, last_seen_at: CarbonInterface|null, blocked: bool}>
     */
    #[Computed]
    public function bannedAddresses(): LengthAwarePaginator
    {
        $banned = $this->state->fail2ban_banned ?? [];
        $page = Paginator::resolveCurrentPage('bannedPage');

        $active = $banned === [] ? collect() : $this->hostileEvents()
            ->whereIn('ip', $banned)
            ->selectRaw('ip, sum(count) as total, max(last_seen_at) as last_seen_at')
            ->groupBy('ip')
            ->orderByDesc('total')
            ->orderBy('ip')
            ->get();

        $all = $active->pluck('ip')->concat(collect($banned)->diff($active->pluck('ip'))->values());
        $rows = $active->keyBy('ip');

        $described = $this->describe(
            $all->forPage($page, self::PER_PAGE)->map(fn (string $ip): SecurityEvent => $rows->get($ip) ?? new SecurityEvent(['ip' => $ip]))->values()
        );

        return new LengthAwarePaginator($described, $all->count(), self::PER_PAGE, $page, [
            'path' => Paginator::resolveCurrentPath(),
            'pageName' => 'bannedPage',
        ]);
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
