@php
    use Swage\SecurityScanner\Enums\EventKind;

    $canManage = auth()->user()->can('update', $server);
    $totals = $this->totals;
    $sshAttempts = collect(EventKind::sshAttempts())->sum(fn ($kind) => $totals[$kind->value] ?? 0);
@endphp

<div class="flex flex-col gap-6" @if ($enabled || $this->blocked->contains(fn ($address) => $address->status->isBusy())) wire:poll.15s @endif>
    <x-panel icon="shield-check" :heading="__('Security scanner')" :description="__('Reads this server\'s SSH, sudo and nginx logs every few minutes for brute force attempts and probing.')">
        <x-slot:actions>
            @if ($enabled && $canManage)
                <flux:button size="sm" variant="ghost" icon="arrow-path" wire:click="scan">{{ __('Scan now') }}</flux:button>
            @endif
        </x-slot:actions>

        <div class="flex flex-col gap-4">
            <flux:switch wire:model.live="enabled" :label="__('Scan this server\'s logs')" :description="__('Only counts and alerts are stored, never whole log lines.')" align="left" :disabled="! $canManage" />

            @if ($this->state->last_error)
                <flux:callout icon="exclamation-triangle" color="red">
                    <flux:callout.heading>{{ __('The last scan failed') }}</flux:callout.heading>
                    <flux:callout.text class="font-mono text-xs">{{ $this->state->last_error }}</flux:callout.text>
                </flux:callout>
            @endif

            @if ($this->state->last_scanned_at)
                <flux:text>{{ __('Last scanned :time.', ['time' => $this->state->last_scanned_at->diffForHumans()]) }}</flux:text>

                <div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
                    @foreach ([
                        __('SSH attempts') => $sshAttempts,
                        __('SSH logins') => $totals[EventKind::SshLogin->value] ?? 0,
                        __('Probes') => $totals[EventKind::HttpProbe->value] ?? 0,
                        __('Login submissions') => $totals[EventKind::HttpLogin->value] ?? 0,
                    ] as $label => $total)
                        <div class="rounded-lg border border-zinc-200 p-4 dark:border-white/8">
                            <flux:text>{{ $label }}</flux:text>
                            <flux:heading size="lg" class="mt-1">{{ number_format($total) }}</flux:heading>
                        </div>
                    @endforeach
                </div>
                <flux:text class="text-xs">{{ __('In the last 24 hours. Swage\'s own SSH logins are not counted.') }}</flux:text>
            @elseif ($enabled)
                <flux:text>{{ __('Waiting for the first scan.') }}</flux:text>
            @endif
        </div>
    </x-panel>

    @if ($this->state->last_scanned_at || $this->alerts->total() > 0)
        <x-panel icon="bell-alert" :heading="__('Open alerts')" :description="__('SSH logins worth a look. Brute force attempts and probing are banned by fail2ban instead.')" flush>
            @if ($canManage && $this->alerts->total() > 0)
                <x-slot:actions>
                    <flux:button size="sm" variant="ghost" icon="check" wire:click="resolveAll">{{ __('Resolve all') }}</flux:button>
                </x-slot:actions>
            @endif

            <flux:table :paginate="$this->alerts" pagination:class="px-5 pb-3">
                <flux:table.columns>
                    <flux:table.column>{{ __('Severity') }}</flux:table.column>
                    <flux:table.column>{{ __('Alert') }}</flux:table.column>
                    <flux:table.column>{{ __('Subject') }}</flux:table.column>
                    <flux:table.column>{{ __('Last seen') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                    @forelse ($this->alerts as $alert)
                        <flux:table.row :key="'alert-'.$alert->id">
                            <flux:table.cell><flux:badge size="sm" :color="$alert->severity->color()">{{ $alert->severity->label() }}</flux:badge></flux:table.cell>
                            <flux:table.cell class="max-w-md">
                                <div class="font-medium">{{ $alert->rule->title() }}</div>
                                <flux:text class="truncate text-xs" :title="$alert->summary()">{{ $alert->summary() }}</flux:text>
                            </flux:table.cell>
                            <flux:table.cell class="font-mono text-xs">
                                {{ $alert->subject }}
                            </flux:table.cell>
                            <flux:table.cell :title="$alert->last_seen_at->toDayDateTimeString()">{{ $alert->last_seen_at->diffForHumans() }}</flux:table.cell>
                            <flux:table.cell align="end">
                                @if ($canManage)
                                    @if (! $this->blocked->contains('ip', $alert->subject))
                                        <flux:button size="sm" variant="ghost" icon="no-symbol" wire:click="blockFromAlert({{ $alert->id }})" wire:confirm.danger="{{ __('Block :ip from SSH and every site on this server?', ['ip' => $alert->subject]) }}" :tooltip="__('Block in the firewall')" />
                                    @endif
                                    <flux:button size="sm" variant="ghost" icon="shield-check" wire:click="trustFromAlert({{ $alert->id }})" wire:confirm="{{ __('Trust :ip? It won\'t be counted, alerted on, blocked or banned by fail2ban.', ['ip' => $alert->subject]) }}" :tooltip="__('Trust')" />
                                    <flux:button size="sm" variant="ghost" icon="check" wire:click="resolve({{ $alert->id }})" :tooltip="__('Resolve')" />
                                @endif
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="5">{{ __('No open alerts.') }}</flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </x-panel>

        <x-panel icon="globe-alt" :heading="__('Busiest hostile addresses')" :description="__('Failed logins, probes, login submissions and denied requests in the last 24 hours. Addresses fail2ban has banned are listed under fail2ban.')" flush>
            @include('security-scanner::address-table', ['addresses' => $this->addresses, 'empty' => __('Nothing hostile in the last 24 hours.')])
        </x-panel>
    @endif

    <x-panel icon="no-symbol" :heading="__('Blocked addresses')" :description="__('Denied by the server\'s firewall, which covers SSH and sites reached directly, and by nginx, which covers sites proxied by Cloudflare, since nginx takes the visitor\'s address from Cloudflare. Cloudflare\'s own addresses are never counted or blocked.')" flush>
        @if ($canManage)
            <x-slot:actions>
                <flux:modal.trigger name="security-scanner-block">
                    <flux:button size="sm" icon="plus">{{ __('Block address') }}</flux:button>
                </flux:modal.trigger>
            </x-slot:actions>
        @endif

        <flux:table :paginate="$this->blockedAddresses" pagination:class="px-5 pb-3">
            <flux:table.columns>
                <flux:table.column>{{ __('Address') }}</flux:table.column>
                <flux:table.column>{{ __('Reason') }}</flux:table.column>
                <flux:table.column>{{ __('Blocked') }}</flux:table.column>
                <flux:table.column>{{ __('Status') }}</flux:table.column>
                <flux:table.column></flux:table.column>
            </flux:table.columns>
            <flux:table.rows>
                @forelse ($this->blockedAddresses as $blocked)
                    <flux:table.row :key="'blocked-'.$blocked->id">
                        <flux:table.cell class="font-mono text-xs">{{ $blocked->ip }}</flux:table.cell>
                        <flux:table.cell class="max-w-md truncate">{{ $blocked->reason ?? '—' }}</flux:table.cell>
                        <flux:table.cell>
                            {{ $blocked->created_at->diffForHumans() }}
                            @if ($blocked->blockedBy)
                                <flux:text class="text-xs">{{ __('by :name', ['name' => $blocked->blockedBy->name]) }}</flux:text>
                            @endif
                        </flux:table.cell>
                        <flux:table.cell><x-status :color="$blocked->status->color()" :label="$blocked->status->label()" /></flux:table.cell>
                        <flux:table.cell align="end">
                            @if ($canManage && ! $blocked->status->isBusy())
                                <flux:button size="sm" variant="ghost" icon="trash" wire:click="unblock({{ $blocked->id }})" wire:confirm="{{ __('Allow connections from :ip again?', ['ip' => $blocked->ip]) }}" :tooltip="__('Unblock')" />
                            @endif
                        </flux:table.cell>
                    </flux:table.row>
                @empty
                    <flux:table.row>
                        <flux:table.cell colspan="5">{{ __('No addresses are blocked.') }}</flux:table.cell>
                    </flux:table.row>
                @endforelse
            </flux:table.rows>
        </flux:table>
    </x-panel>

    <x-panel icon="shield-check" :heading="__('Trusted addresses')" :description="__('Addresses and ranges you trust, such as your office\'s. They\'re never counted, alerted on or blocked, fail2ban never bans them, and AI reviews leave them out.')" flush>
        @if ($canManage)
            <x-slot:actions>
                <flux:modal.trigger name="security-scanner-trust">
                    <flux:button size="sm" icon="plus">{{ __('Trust address') }}</flux:button>
                </flux:modal.trigger>
            </x-slot:actions>
        @endif

        <flux:table>
            <flux:table.columns>
                <flux:table.column>{{ __('Address') }}</flux:table.column>
                <flux:table.column>{{ __('Note') }}</flux:table.column>
                <flux:table.column>{{ __('Trusted') }}</flux:table.column>
                <flux:table.column></flux:table.column>
            </flux:table.columns>
            <flux:table.rows>
                @forelse ($this->trustedAddresses as $trusted)
                    <flux:table.row :key="'trusted-'.$trusted->id">
                        <flux:table.cell class="font-mono text-xs">{{ $trusted->ip }}</flux:table.cell>
                        <flux:table.cell class="max-w-md truncate">{{ $trusted->swage_host ? __('Swage Host') : ($trusted->note ?? '—') }}</flux:table.cell>
                        <flux:table.cell>
                            {{ $trusted->created_at->diffForHumans() }}
                            @if ($trusted->trustedBy)
                                <flux:text class="text-xs">{{ __('by :name', ['name' => $trusted->trustedBy->name]) }}</flux:text>
                            @endif
                        </flux:table.cell>
                        <flux:table.cell align="end">
                            @if ($trusted->swage_host)
                                <flux:tooltip :content="__('Swage connects to this server from here, so it\'s always trusted.')">
                                    <flux:icon.lock-closed variant="micro" class="me-2 inline text-zinc-400" />
                                </flux:tooltip>
                            @elseif ($canManage)
                                <flux:button size="sm" variant="ghost" icon="trash" wire:click="untrust({{ $trusted->id }})" wire:confirm="{{ __('Stop trusting :ip? It will be counted again, and fail2ban can ban it.', ['ip' => $trusted->ip]) }}" :tooltip="__('Stop trusting')" />
                            @endif
                        </flux:table.cell>
                    </flux:table.row>
                @empty
                    <flux:table.row>
                        <flux:table.cell colspan="4">{{ __('No addresses are trusted.') }}</flux:table.cell>
                    </flux:table.row>
                @endforelse
            </flux:table.rows>
        </flux:table>
    </x-panel>

    <x-panel icon="lock-closed" :heading="__('fail2ban')" :description="__('Bans addresses for good from SSH after :ssh failed logins in a day, and from sites after :probes probes for vulnerable files in a day, in nginx too, so visitors through Cloudflare are banned as well. Trusting an address lifts its ban.', ['ssh' => config('security-scanner.fail2ban_ssh'), 'probes' => config('security-scanner.fail2ban_probes')])">
        @if ($this->state->fail2ban_installed)
            @if ($this->state->needsFail2banUpdate())
                <flux:callout icon="arrow-path" color="amber" class="mb-4">
                    @if ($this->state->fail2banCanBanPanel())
                        <flux:callout.heading>{{ __('fail2ban could lock Swage out of this server') }}</flux:callout.heading>
                        <flux:callout.text>{{ __('It was installed before it left Swage\'s own address alone, so a few failed logins or probes from that address would ban Swage. Update it to exempt the address.') }}</flux:callout.text>
                    @elseif ($this->state->fail2banBansTemporarily())
                        <flux:callout.heading>{{ __('fail2ban lets banned addresses back in') }}</flux:callout.heading>
                        <flux:callout.text>{{ __('It was installed before bans were permanent, so addresses come back once their ban ends. Update it to ban them for good after :ssh failed SSH logins or :probes probes in a day.', ['ssh' => config('security-scanner.fail2ban_ssh'), 'probes' => config('security-scanner.fail2ban_probes')]) }}</flux:callout.text>
                    @elseif ($this->state->fail2banMissesRepeatOffenders())
                        <flux:callout.heading>{{ __('fail2ban never bans addresses for a week') }}</flux:callout.heading>
                        <flux:callout.text>{{ __('Its recidive jail can\'t see fail2ban\'s bans, so addresses banned for an hour come back as soon as the ban ends. Update it to ban them for a week after three bans in a day.') }}</flux:callout.text>
                    @elseif ($this->state->fail2banMissesPacedSsh())
                        <flux:callout.heading>{{ __('fail2ban misses slow SSH attacks') }}</flux:callout.heading>
                        <flux:callout.text>{{ __('It only bans addresses after five failed logins in ten minutes, so attackers who pace their guesses are never banned. Update it to count failed logins over an hour.') }}</flux:callout.text>
                    @else
                        <flux:callout.heading>{{ __('fail2ban doesn\'t ban probing yet') }}</flux:callout.heading>
                        <flux:callout.text>{{ __('It was installed before the scanner could ban addresses probing sites. Update it to add the probes jail.') }}</flux:callout.text>
                    @endif
                    @if ($canManage)
                        <x-slot:actions>
                            <flux:button size="sm" icon="arrow-path" wire:click="installFail2ban">{{ __('Update fail2ban') }}</flux:button>
                        </x-slot:actions>
                    @endif
                </flux:callout>
            @endif
            <div class="flex flex-wrap items-center justify-between gap-2">
                <flux:text>{{ trans_choice('{0} Installed. No addresses are banned right now.|{1} Installed. :count address is banned right now.|[2,*] Installed. :count addresses are banned right now.', $this->bannedCount, ['count' => number_format($this->bannedCount)]) }}</flux:text>
                @if ($canManage && $this->bannedCount > 0)
                    <flux:button size="sm" variant="ghost" icon="trash" wire:click="unbanAll" wire:confirm="{{ __('Lift every fail2ban ban on this server? Banned addresses can reach SSH and the sites again until they fail enough to be banned again. Addresses blocked from this panel stay blocked.') }}">{{ __('Unban all') }}</flux:button>
                @endif
            </div>
            @if ($this->bannedAddresses->total() > 0)
                <div class="mt-4">
                    @include('security-scanner::address-table', ['addresses' => $this->bannedAddresses, 'empty' => '', 'paginationClass' => ''])
                </div>
            @endif
        @else
            <flux:text>{{ $this->state->fail2ban_installed === false ? __('fail2ban is not installed on this server.') : __('Whether fail2ban is installed shows after the first scan.') }}</flux:text>
            @if ($canManage)
                <flux:button size="sm" icon="arrow-down-tray" class="mt-4" wire:click="installFail2ban">{{ __('Install fail2ban') }}</flux:button>
            @endif
        @endif
    </x-panel>

    <flux:modal name="security-scanner-trust" class="w-full max-w-lg">
        <form wire:submit="trust" class="flex flex-col gap-6">
            <div>
                <flux:heading size="lg">{{ __('Trust address') }}</flux:heading>
                <flux:text class="mt-1">{{ __('What the scanner recorded about it is cleared, it\'s unblocked, and fail2ban lifts any ban on it.') }}</flux:text>
            </div>
            <flux:input wire:model="trustIp" :label="__('IP address or range')" placeholder="203.0.113.0/24" class="font-mono" required />
            <flux:input wire:model="trustNote" :label="__('Note')" :placeholder="__('Optional, such as Office')" />
            <div class="flex justify-end gap-2">
                <flux:modal.close>
                    <flux:button variant="ghost">{{ __('Cancel') }}</flux:button>
                </flux:modal.close>
                <flux:button type="submit" variant="primary">{{ __('Trust') }}</flux:button>
            </div>
        </form>
    </flux:modal>

    <flux:modal name="security-scanner-block" class="w-full max-w-lg">
        <form wire:submit="block" class="flex flex-col gap-6">
            <flux:heading size="lg">{{ __('Block address') }}</flux:heading>
            <flux:input wire:model="ip" :label="__('IP address')" placeholder="203.0.113.7" class="font-mono" required />
            <flux:input wire:model="reason" :label="__('Reason')" :placeholder="__('Optional')" />
            <div class="flex justify-end gap-2">
                <flux:modal.close>
                    <flux:button variant="ghost">{{ __('Cancel') }}</flux:button>
                </flux:modal.close>
                <flux:button type="submit" variant="danger">{{ __('Block') }}</flux:button>
            </div>
        </form>
    </flux:modal>
</div>
