<flux:table>
    <flux:table.columns>
        <flux:table.column>{{ __('Address') }}</flux:table.column>
        <flux:table.column>{{ __('Events') }}</flux:table.column>
        <flux:table.column>{{ __('What') }}</flux:table.column>
        <flux:table.column>{{ __('Last seen') }}</flux:table.column>
        <flux:table.column></flux:table.column>
    </flux:table.columns>
    <flux:table.rows>
        @forelse ($addresses as $address)
            <flux:table.row :key="'address-'.$address['ip']">
                <flux:table.cell class="font-mono text-xs">
                    {{ $address['ip'] }}
                    @if ($address['blocked'])
                        <flux:badge size="sm" color="red" class="ms-1">{{ __('Blocked') }}</flux:badge>
                    @endif
                </flux:table.cell>
                <flux:table.cell>{{ number_format($address['total']) }}</flux:table.cell>
                <flux:table.cell class="max-w-md truncate text-xs">
                    {{ collect($address['kinds'])->map(fn ($count, $label) => "{$label}: {$count}")->implode(' · ') ?: '—' }}
                </flux:table.cell>
                <flux:table.cell :title="$address['last_seen_at']?->toDayDateTimeString()">{{ $address['last_seen_at']?->diffForHumans() ?? __('Not in the last 24 hours') }}</flux:table.cell>
                <flux:table.cell align="end">
                    @if ($canManage && ! $address['blocked'])
                        <flux:button size="sm" variant="ghost" icon="no-symbol" wire:click="block('{{ $address['ip'] }}')" wire:confirm.danger="{{ __('Block every connection from :ip, including SSH and HTTP?', ['ip' => $address['ip']]) }}" :tooltip="__('Block in the firewall')" />
                    @endif
                </flux:table.cell>
            </flux:table.row>
        @empty
            <flux:table.row>
                <flux:table.cell colspan="5">{{ $empty }}</flux:table.cell>
            </flux:table.row>
        @endforelse
    </flux:table.rows>
</flux:table>
