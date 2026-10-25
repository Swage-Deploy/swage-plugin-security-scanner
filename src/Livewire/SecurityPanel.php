<?php

namespace Swage\SecurityScanner\Livewire;

use App\Enums\ResourceStatus;
use App\Models\Server;
use Carbon\CarbonInterface;
use Closure;
use Flux\Flux;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Collection as SupportCollection;
use Illuminate\Validation\ValidationException;
use Livewire\Attributes\Computed;
use Livewire\Component;
use Swage\SecurityScanner\CloudflareAddresses;
use Swage\SecurityScanner\Enums\EventKind;
use Swage\SecurityScanner\Jobs\BlockAddress;
use Swage\SecurityScanner\Jobs\InstallFail2ban;
use Swage\SecurityScanner\Jobs\ScanServerLogs;
use Swage\SecurityScanner\Jobs\UnblockAddress;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\SecurityAlert;
use Swage\SecurityScanner\Models\SecurityEvent;

/**
 * The security scanner's panel on a server's Plugins tab: whether scanning is on, open alerts, the busiest hostile
 * addresses of the last day, and the addresses blocked in the firewall.
 */
class SecurityPanel extends Component
{
    public Server $server;

    public bool $enabled = false;

    public string $ip = '';

    public string $reason = '';

    public function mount(): void
    {
        $this->authorize('view', $this->server);

        $this->enabled = $this->state->enabled;
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

        if ($alert->rule->concernsAddress()) {
            $this->block($alert->subject, $alert->rule->title());
        }
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

        Flux::toast(variant: 'success', text: __('Installing fail2ban. It shows as installed after the next scan.'));
    }

    /**
     * @return Collection<int, SecurityAlert>
     */
    #[Computed]
    public function alerts(): Collection
    {
        return SecurityAlert::query()
            ->where('server_id', $this->server->id)
            ->open()
            ->latest('last_seen_at')
            ->limit(50)
            ->get()
            ->sortByDesc(fn (SecurityAlert $alert): int => $alert->severity->rank())
            ->values();
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
     * @return SupportCollection<int, array{ip: string, total: int, kinds: array<string, int>, last_seen_at: CarbonInterface|null, blocked: bool}>
     */
    #[Computed]
    public function addresses(): SupportCollection
    {
        return $this->hostileAddresses(fn (Builder $query) => $query->whereNotIn('ip', $this->state->fail2ban_banned ?? [])->limit(10));
    }

    /**
     * The addresses fail2ban has banned, with what they did in the last day. An address banned for longer, such as by
     * the week long recidive jail, may have nothing recorded in the last day.
     *
     * @return SupportCollection<int, array{ip: string, total: int, kinds: array<string, int>, last_seen_at: CarbonInterface|null, blocked: bool}>
     */
    #[Computed]
    public function bannedAddresses(): SupportCollection
    {
        $banned = $this->state->fail2ban_banned ?? [];

        if ($banned === []) {
            return collect();
        }

        $active = $this->hostileAddresses(fn (Builder $query) => $query->whereIn('ip', $banned));
        $blocked = $this->blockedAddresses->pluck('ip');

        return $active->concat(
            collect($banned)
                ->diff($active->pluck('ip'))
                ->map(fn (string $ip): array => ['ip' => $ip, 'total' => 0, 'kinds' => [], 'last_seen_at' => null, 'blocked' => $blocked->contains($ip)])
        )->values();
    }

    /**
     * Rank addresses by their hostile events in the last day, and say what the events were and when the address was
     * last seen.
     *
     * @param  Closure(Builder<SecurityEvent>): mixed  $scope
     * @return SupportCollection<int, array{ip: string, total: int, kinds: array<string, int>, last_seen_at: CarbonInterface|null, blocked: bool}>
     */
    protected function hostileAddresses(Closure $scope): SupportCollection
    {
        $query = fn () => SecurityEvent::query()
            ->where('server_id', $this->server->id)
            ->whereNotNull('ip')
            ->whereIn('kind', EventKind::hostile())
            ->where('last_seen_at', '>=', now()->subDay());

        $top = $query()
            ->selectRaw('ip, sum(count) as total, max(last_seen_at) as last_seen_at')
            ->groupBy('ip')
            ->orderByDesc('total')
            ->tap($scope)
            ->get();

        $kinds = $query()->whereIn('ip', $top->pluck('ip'))->selectRaw('ip, kind, sum(count) as total')->groupBy('ip', 'kind')->get()->groupBy('ip');
        $blocked = $this->blockedAddresses->pluck('ip');

        return $top->map(fn (SecurityEvent $row): array => [
            'ip' => $row->ip,
            'total' => (int) $row->total,
            'kinds' => $kinds->get($row->ip, collect())->mapWithKeys(fn (SecurityEvent $kind): array => [$kind->kind->label() => (int) $kind->total])->sortDesc()->all(),
            'last_seen_at' => $row->last_seen_at,
            'blocked' => $blocked->contains($row->ip),
        ])->values();
    }

    /**
     * @return Collection<int, BlockedAddress>
     */
    #[Computed]
    public function blockedAddresses(): Collection
    {
        return BlockedAddress::query()->where('server_id', $this->server->id)->with('blockedBy')->latest()->get();
    }

    public function render(): View
    {
        return view('security-scanner::panel');
    }
}
