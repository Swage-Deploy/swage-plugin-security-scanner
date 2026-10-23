<?php

namespace Swage\SecurityScanner\Livewire;

use App\Enums\ResourceStatus;
use App\Models\Server;
use Flux\Flux;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Collection as SupportCollection;
use Illuminate\Validation\ValidationException;
use Livewire\Attributes\Computed;
use Livewire\Component;
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
        Flux::toast(variant: 'success', text: __('Blocking :ip in the firewall.', ['ip' => $address->ip]));
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
     * The addresses with the most hostile events in the last day, and what they were.
     *
     * @return SupportCollection<int, array{ip: string, total: int, kinds: array<string, int>, banned: bool, blocked: bool}>
     */
    #[Computed]
    public function addresses(): SupportCollection
    {
        $query = fn () => SecurityEvent::query()
            ->where('server_id', $this->server->id)
            ->whereNotNull('ip')
            ->whereIn('kind', EventKind::hostile())
            ->where('last_seen_at', '>=', now()->subDay());

        $top = $query()->selectRaw('ip, sum(count) as total')->groupBy('ip')->orderByDesc('total')->limit(10)->pluck('total', 'ip');

        $kinds = $query()->whereIn('ip', $top->keys())->selectRaw('ip, kind, sum(count) as total')->groupBy('ip', 'kind')->get()->groupBy('ip');
        $blocked = $this->blockedAddresses->pluck('ip');

        return $top->map(fn (mixed $total, string $ip): array => [
            'ip' => $ip,
            'total' => (int) $total,
            'kinds' => $kinds->get($ip, collect())->mapWithKeys(fn (SecurityEvent $row): array => [$row->kind->label() => (int) $row->total])->sortDesc()->all(),
            'banned' => $this->state->isBannedByFail2ban($ip),
            'blocked' => $blocked->contains($ip),
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
