@php
    use Swage\SecurityScanner\Enums\EventKind;

    $canManage = auth()->user()->can('update', $server);
    $totals = $this->totals;
    $sshAttempts = collect(EventKind::sshAttempts())->sum(fn ($kind) => $totals[$kind->value] ?? 0);
@endphp

<div class="flex flex-col gap-6" @if ($enabled || $aiEnabled || $this->blocked->contains(fn ($address) => $address->status->isBusy())) wire:poll.15s @endif>
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
                                    <flux:button size="sm" variant="ghost" icon="shield-check" wire:click="trustFromAlert({{ $alert->id }})" wire:confirm="{{ __('Trust :ip? It won\'t be counted, alerted on, blocked or banned by fail2ban, and the AI review will leave it out.', ['ip' => $alert->subject]) }}" :tooltip="__('Trust')" />
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

    <x-panel icon="shield-check" :heading="__('Trusted addresses')" :description="__('Addresses and ranges you trust, such as your office\'s. They\'re never counted, alerted on or blocked, fail2ban never bans them, and the AI review leaves them out.')" flush>
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

    <x-panel icon="sparkles" :heading="__('AI review')" :description="__('An AI model reads what the scanner recorded and a read-only snapshot of how this server is set up, and suggests what to look at. It can\'t change anything: its suggestions are only shown here for you to act on.')">
        @if ($aiEnabled && $canManage && $this->ai->isConfigured())
            <x-slot:actions>
                <flux:button size="sm" variant="ghost" icon="arrow-path" wire:click="review">{{ __('Review now') }}</flux:button>
            </x-slot:actions>
        @endif

        <div class="flex flex-col gap-6">
            @if (! $this->ai::supported())
                <flux:text>{{ __('The AI review needs Swage v1.3.0 or later.') }}</flux:text>
            @elseif (! $this->ai->isConfigured())
                <flux:callout icon="cog-6-tooth" color="zinc">
                    <flux:callout.text>{{ __('Set the OpenAI compatible API to use, and its model, on the plugin\'s config page first.') }}</flux:callout.text>
                    @can('administer')
                        <x-slot:actions>
                            <flux:button size="sm" icon="cog-6-tooth" :href="route('plugins.configure', ['server', 'security-scanner'])" wire:navigate>{{ __('Configure') }}</flux:button>
                        </x-slot:actions>
                    @endcan
                </flux:callout>
            @endif

            @if ($this->ai->isConfigured() || $aiEnabled)
                <flux:switch wire:model.live="aiEnabled" :label="__('Review this server with AI')" align="left" :disabled="! $canManage || ! $this->ai->isConfigured()"
                    :description="__('Every :hours hours. The scanner\'s counts alerts and blocks with the addresses and usernames in them, and the snapshot of the server\'s SSH settings, open ports, firewall, updates and accounts are sent to :host.', ['hours' => config('security-scanner.ai.interval_hours'), 'host' => $this->ai->host() ?? __('the configured API')])" />
                <flux:error name="aiEnabled" />
            @endif

            @if ($this->state->ai_error)
                <flux:callout icon="exclamation-triangle" color="red">
                    <flux:callout.heading>{{ __('The last review failed') }}</flux:callout.heading>
                    <flux:callout.text class="font-mono text-xs">{{ $this->state->ai_error }}</flux:callout.text>
                </flux:callout>
            @endif

            @if ($review = $this->latestReview)
                <div class="flex flex-col gap-1">
                    <flux:text class="text-zinc-800 dark:text-zinc-200">{{ $review->summary }}</flux:text>
                    <div class="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <flux:text class="text-xs">
                            {{ __('Reviewed :time by :model.', ['time' => $review->created_at->diffForHumans(), 'model' => $review->reported_model && $review->reported_model !== $review->model ? "{$review->model} ({$review->reported_model})" : $review->model]) }}
                            @if ($review->input_tokens)
                                {{ __('Read :input tokens and wrote :output.', ['input' => number_format($review->input_tokens), 'output' => number_format((int) $review->output_tokens)]) }}
                            @endif
                        </flux:text>
                        @if ($canManage)
                            <flux:button size="xs" variant="ghost" icon="document-magnifying-glass" wire:click="showReviewInput">{{ __('What was sent') }}</flux:button>
                        @endif
                    </div>
                </div>

                @if ($review->missingLabels() !== [])
                    <flux:callout icon="exclamation-triangle" color="amber">
                        <flux:callout.heading>{{ __('Parts of the server couldn\'t be read') }}</flux:callout.heading>
                        <flux:callout.text>{{ __('The review didn\'t see: :parts. A command failed or isn\'t installed, so anything wrong there wasn\'t checked.', ['parts' => implode(', ', $review->missingLabels())]) }}</flux:callout.text>
                    </flux:callout>
                @endif

                @php
                    $ignoredKeys = $this->ignoredFindings->pluck('key')->all();
                    [$ignoredNow, $findings] = collect($review->sortedFindings())->partition(fn ($finding) => in_array($finding['key'], $ignoredKeys, true));
                @endphp

                @if ($findings->isEmpty())
                    <flux:text>{{ $ignoredNow->isEmpty() ? __('Nothing needs attention.') : __('Nothing needs attention apart from what\'s ignored.') }}</flux:text>
                @else
                    <div class="flex flex-col divide-y divide-zinc-200 rounded-lg border border-zinc-200 dark:divide-white/8 dark:border-white/8">
                        @foreach ($findings as $finding)
                            <div class="flex flex-col gap-3 p-4" wire:key="finding-{{ $review->id }}-{{ $finding['key'] }}">
                                <div class="flex items-center gap-2">
                                    <flux:badge size="sm" :color="$finding['severity']->color()">{{ $finding['severity']->label() }}</flux:badge>
                                    <span class="font-medium text-zinc-900 dark:text-white">{{ $finding['title'] }}</span>
                                    @if ($canManage)
                                        <flux:button size="xs" variant="ghost" icon="eye-slash" class="ms-auto" wire:click="ignoreFinding('{{ $finding['key'] }}')">{{ __('Ignore') }}</flux:button>
                                    @endif
                                </div>
                                <flux:text class="whitespace-pre-line">{{ $finding['detail'] }}</flux:text>
                                @if (filled($finding['suggestion']))
                                    <details class="group" wire:key="suggestion-{{ $review->id }}-{{ $finding['key'] }}" wire:ignore.self>
                                        <summary class="flex w-fit cursor-pointer list-none items-center gap-1 text-xs font-medium text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 [&::-webkit-details-marker]:hidden">
                                            <flux:icon.chevron-right variant="micro" class="transition-transform group-open:rotate-90" />
                                            {{ __('Suggestion') }}
                                        </summary>
                                        <div class="mt-2 rounded-md bg-zinc-50 p-3 dark:bg-white/5">
                                            <flux:text class="whitespace-pre-line break-words">{{ $finding['suggestion'] }}</flux:text>
                                        </div>
                                    </details>
                                @endif
                            </div>
                        @endforeach
                    </div>
                    <flux:text class="text-xs">{{ __('Suggestions come from an AI model and can be wrong. Check them before acting, and don\'t run a command you don\'t understand. Swage never runs them.') }}</flux:text>
                @endif

                @if ($this->ignoredFindings->isNotEmpty())
                    <div>
                        <flux:text class="text-xs font-medium uppercase tracking-wide">{{ __('Ignored') }}</flux:text>
                        <flux:text class="mt-1 text-xs">{{ __('Reviews still check for these, but they aren\'t listed with the findings to act on.') }}</flux:text>
                        <div class="mt-2 flex flex-col divide-y divide-zinc-200 rounded-lg border border-zinc-200 dark:divide-white/8 dark:border-white/8">
                            @foreach ($this->ignoredFindings as $ignored)
                                @php($current = $ignoredNow->firstWhere('key', $ignored->key))
                                <div class="flex flex-col gap-1 px-4 py-3" wire:key="ignored-{{ $ignored->id }}">
                                    <div class="flex items-center gap-2">
                                        @if ($current)
                                            <flux:badge size="sm" :color="$current['severity']->color()">{{ $current['severity']->label() }}</flux:badge>
                                        @endif
                                        <span class="text-sm font-medium text-zinc-800 dark:text-zinc-200">{{ $current['title'] ?? $ignored->title }}</span>
                                        @if ($canManage)
                                            <flux:button size="xs" variant="ghost" icon="eye" class="ms-auto" wire:click="stopIgnoring({{ $ignored->id }})">{{ __('Stop ignoring') }}</flux:button>
                                        @endif
                                    </div>
                                    <flux:text class="text-xs">
                                        {{ $current ? __('Still reported by the latest review.') : __('Not reported by the latest review.') }}
                                        {{ $ignored->ignoredBy ? __('Ignored by :name :time.', ['name' => $ignored->ignoredBy->name, 'time' => $ignored->created_at->diffForHumans()]) : __('Ignored :time.', ['time' => $ignored->created_at->diffForHumans()]) }}
                                    </flux:text>
                                    @if ($current)
                                        <details class="group text-sm" wire:key="ignored-said-{{ $ignored->id }}" wire:ignore.self>
                                            <summary class="flex w-fit cursor-pointer list-none items-center gap-1 text-xs font-medium text-zinc-500 hover:text-zinc-800 dark:text-zinc-400 dark:hover:text-zinc-200 [&::-webkit-details-marker]:hidden">
                                                <flux:icon.chevron-right variant="micro" class="transition-transform group-open:rotate-90" />
                                                {{ __('What the review said') }}
                                            </summary>
                                            <flux:text class="mt-2 whitespace-pre-line">{{ $current['detail'] }}</flux:text>
                                            @if (filled($current['suggestion']))
                                                <flux:text class="mt-2 whitespace-pre-line break-words">{{ $current['suggestion'] }}</flux:text>
                                            @endif
                                        </details>
                                    @endif
                                </div>
                            @endforeach
                        </div>
                    </div>
                @endif

                @if (filled($review->checked))
                    <details class="group rounded-lg border border-zinc-200 dark:border-white/8" wire:key="checked-{{ $review->id }}" wire:ignore.self>
                        <summary class="flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-sm font-medium text-zinc-800 dark:text-zinc-200 [&::-webkit-details-marker]:hidden">
                            <flux:icon.chevron-right variant="micro" class="text-zinc-400 transition-transform group-open:rotate-90" />
                            {{ __('What was checked') }}
                            <flux:badge size="sm" color="zinc">{{ count($review->checked) }}</flux:badge>
                        </summary>
                        <dl class="grid gap-x-6 gap-y-3 border-t border-zinc-200 px-4 py-4 text-sm sm:grid-cols-[minmax(0,12rem)_1fr] dark:border-white/8">
                            @foreach ($review->checked as $entry)
                                <dt class="font-medium text-zinc-800 dark:text-zinc-200" wire:key="checked-{{ $review->id }}-{{ $loop->index }}">{{ $entry['area'] }}</dt>
                                <dd class="-mt-2 text-zinc-600 sm:mt-0 dark:text-zinc-400">{{ $entry['observation'] }}</dd>
                            @endforeach
                        </dl>
                    </details>
                @else
                    <flux:callout icon="question-mark-circle" color="amber">
                        <flux:callout.text>{{ __('The model didn\'t say what it checked, so there\'s no sign it read the server. Try Review now, or a model that follows instructions more closely.') }}</flux:callout.text>
                    </flux:callout>
                @endif
            @elseif ($aiEnabled)
                <flux:text>{{ __('Waiting for the first review.') }}</flux:text>
            @endif
        </div>
    </x-panel>

    <flux:modal name="security-scanner-review-input" class="w-full max-w-4xl">
        <div class="flex flex-col gap-4">
            <div>
                <flux:heading size="lg">{{ __('What the review was sent') }}</flux:heading>
                <flux:text class="mt-1">{{ __('Everything the AI model was given for the latest review, exactly as it was sent, after its instructions.') }}</flux:text>
            </div>
            <pre class="max-h-[60vh] overflow-auto rounded-lg bg-zinc-50 p-4 font-mono text-xs whitespace-pre-wrap break-words text-zinc-800 dark:bg-white/5 dark:text-zinc-200">{{ $reviewInput ?: __('This review was made before Swage kept what reviews were sent.') }}</pre>
        </div>
    </flux:modal>

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
