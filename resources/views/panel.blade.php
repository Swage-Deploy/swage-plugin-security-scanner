@php
    use Swage\SecurityScanner\Enums\EventKind;

    $canManage = auth()->user()->can('update', $server);
    $totals = $this->totals;
    $sshAttempts = collect(EventKind::sshAttempts())->sum(fn ($kind) => $totals[$kind->value] ?? 0);
@endphp

<div class="flex flex-col gap-6" @if ($enabled || $this->blockedAddresses->contains(fn ($address) => $address->status->isBusy())) wire:poll.15s @endif>
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

    @if ($this->state->last_scanned_at || $this->alerts->isNotEmpty())
        <x-panel icon="bell-alert" :heading="__('Open alerts')" flush>
            @if ($canManage && $this->alerts->isNotEmpty())
                <x-slot:actions>
                    <flux:button size="sm" variant="ghost" icon="check" wire:click="resolveAll">{{ __('Resolve all') }}</flux:button>
                </x-slot:actions>
            @endif

            <flux:table>
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
                                @if ($alert->rule->concernsAddress() && $this->state->isBannedByFail2ban($alert->subject))
                                    <flux:badge size="sm" class="ms-1">{{ __('Banned by fail2ban') }}</flux:badge>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell :title="$alert->last_seen_at->toDayDateTimeString()">{{ $alert->last_seen_at->diffForHumans() }}</flux:table.cell>
                            <flux:table.cell align="end">
                                @if ($canManage)
                                    @if ($alert->rule->concernsAddress() && ! $this->blockedAddresses->contains('ip', $alert->subject))
                                        <flux:button size="sm" variant="ghost" icon="no-symbol" wire:click="blockFromAlert({{ $alert->id }})" wire:confirm.danger="{{ __('Block every connection from :ip, including SSH and HTTP?', ['ip' => $alert->subject]) }}" :tooltip="__('Block in the firewall')" />
                                    @endif
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

        <x-panel icon="globe-alt" :heading="__('Busiest hostile addresses')" :description="__('Failed logins, probes, login submissions and denied requests in the last 24 hours.')" flush>
            <flux:table>
                <flux:table.columns>
                    <flux:table.column>{{ __('Address') }}</flux:table.column>
                    <flux:table.column>{{ __('Events') }}</flux:table.column>
                    <flux:table.column>{{ __('What') }}</flux:table.column>
                    <flux:table.column>{{ __('Last seen') }}</flux:table.column>
                    <flux:table.column></flux:table.column>
                </flux:table.columns>
                <flux:table.rows>
                    @forelse ($this->addresses as $address)
                        <flux:table.row :key="'address-'.$address['ip']">
                            <flux:table.cell class="font-mono text-xs">
                                {{ $address['ip'] }}
                                @if ($address['banned'])
                                    <flux:badge size="sm" class="ms-1">{{ __('Banned by fail2ban') }}</flux:badge>
                                @endif
                                @if ($address['blocked'])
                                    <flux:badge size="sm" color="red" class="ms-1">{{ __('Blocked') }}</flux:badge>
                                @endif
                            </flux:table.cell>
                            <flux:table.cell>{{ number_format($address['total']) }}</flux:table.cell>
                            <flux:table.cell class="max-w-md truncate text-xs">
                                {{ collect($address['kinds'])->map(fn ($count, $label) => "{$label}: {$count}")->implode(' · ') }}
                            </flux:table.cell>
                            <flux:table.cell :title="$address['last_seen_at']->toDayDateTimeString()">{{ $address['last_seen_at']->diffForHumans() }}</flux:table.cell>
                            <flux:table.cell align="end">
                                @if ($canManage && ! $address['blocked'])
                                    <flux:button size="sm" variant="ghost" icon="no-symbol" wire:click="block('{{ $address['ip'] }}')" wire:confirm.danger="{{ __('Block every connection from :ip, including SSH and HTTP?', ['ip' => $address['ip']]) }}" :tooltip="__('Block in the firewall')" />
                                @endif
                            </flux:table.cell>
                        </flux:table.row>
                    @empty
                        <flux:table.row>
                            <flux:table.cell colspan="5">{{ __('Nothing hostile in the last 24 hours.') }}</flux:table.cell>
                        </flux:table.row>
                    @endforelse
                </flux:table.rows>
            </flux:table>
        </x-panel>
    @endif

    <x-panel icon="no-symbol" :heading="__('Blocked addresses')" :description="__('Denied everything by the server\'s firewall. Sites proxied by Cloudflare reach the server from Cloudflare\'s addresses, so blocking a visitor there has to be done in Cloudflare.')" flush>
        @if ($canManage)
            <x-slot:actions>
                <flux:modal.trigger name="security-scanner-block">
                    <flux:button size="sm" icon="plus">{{ __('Block address') }}</flux:button>
                </flux:modal.trigger>
            </x-slot:actions>
        @endif

        <flux:table>
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

    <x-panel icon="lock-closed" :heading="__('fail2ban')" :description="__('Bans addresses from SSH for an hour after five failed logins in ten minutes, and for a week once banned three times in a day.')">
        @if ($this->state->fail2ban_installed)
            <flux:text>{{ trans_choice('Installed. No addresses are banned right now.|Installed. :count address is banned right now.|Installed. :count addresses are banned right now.', count($this->state->fail2ban_banned ?? []), ['count' => count($this->state->fail2ban_banned ?? [])]) }}</flux:text>
        @else
            <flux:text>{{ $this->state->fail2ban_installed === false ? __('fail2ban is not installed on this server.') : __('Whether fail2ban is installed shows after the first scan.') }}</flux:text>
            @if ($canManage)
                <flux:button size="sm" icon="arrow-down-tray" class="mt-4" wire:click="installFail2ban">{{ __('Install fail2ban') }}</flux:button>
            @endif
        @endif
    </x-panel>

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
