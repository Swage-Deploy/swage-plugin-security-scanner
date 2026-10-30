<?php

namespace Swage\SecurityScanner\Scanning;

use App\Enums\ResourceStatus;
use App\Ssh\RemoteShell;
use RuntimeException;
use Swage\SecurityScanner\CloudflareAddresses;
use Swage\SecurityScanner\Jobs\BlockAddress;
use Swage\SecurityScanner\Jobs\UpdateFail2banTrustedAddresses;
use Swage\SecurityScanner\Models\BlockedAddress;
use Swage\SecurityScanner\Models\ScannerState;
use Swage\SecurityScanner\Models\TrustedAddress;

/**
 * Reads what a server's logs gained since the last scan, counts it and raises alerts from it. Events from Cloudflare's
 * own addresses, and from addresses trusted on the server, are left out, so they are never ranked, alerted on or
 * blocked.
 */
class LogScanner
{
    public function __construct(
        protected RemoteShell $shell,
        protected SshLogParser $sshParser,
        protected NginxAccessParser $nginxParser,
        protected EventRecorder $recorder,
        protected ThreatDetector $detector,
    ) {}

    /**
     * @return list<LogEvent> The events the scan read.
     *
     * @throws RuntimeException when the server cannot be read.
     */
    public function scan(ScannerState $state): array
    {
        $script = ScanScript::make();
        $result = $this->shell->run($state->server, $script->render($state->cursors ?? []), timeout: 60);

        if ($result->failed()) {
            throw new RuntimeException(trim("Reading the server's logs failed with exit code {$result->exitCode}. ".mb_strimwidth($result->output, 0, 500, '…')));
        }

        $output = $script->parse($result->output);
        $panelAddress = $output->clientAddress ?? $state->panel_address;

        $events = $this->sshParser->parse($output->journalLines, $panelAddress);

        foreach ($output->files as $file) {
            array_push($events, ...$this->nginxParser->parse($file->lines(), $file->source()));
        }

        if (TrustedAddress::trustSwageHost($state->server_id, $panelAddress)) {
            UpdateFail2banTrustedAddresses::dispatch($state->server);
        }

        $trusted = TrustedAddress::rangesFor($state->server_id);

        $events = array_values(array_filter($events, fn (LogEvent $event): bool => $event->ip === null
            || (! CloudflareAddresses::contains($event->ip) && ! TrustedAddress::covers($trusted, $event->ip))));

        $this->recorder->record($state->server, $events);
        $this->detector->detect($state, $events);

        $state->update([
            'cursors' => $this->cursors($state, $output),
            'panel_address' => $panelAddress,
            'fail2ban_installed' => $output->fail2banInstalled,
            'fail2ban_jails' => $output->fail2banJails,
            'fail2ban_banned' => $output->fail2banBanned,
            'fail2ban_ignores_panel' => $output->fail2banIgnoresPanel,
            'fail2ban_recidive_reads_log' => $output->fail2banRecidiveReadsLog,
            'fail2ban_sshd_counts_hour' => $output->fail2banSshdCountsHour,
            'fail2ban_bans_permanently' => $output->fail2banBansPermanently,
            'last_scanned_at' => now(),
            'last_error' => null,
        ]);

        $this->restoreNginxBlocks($state, $output);

        return $events;
    }

    /**
     * Block again the addresses missing from nginx's deny list, such as ones blocked before the list existed, or on a
     * server whose nginx config was rebuilt.
     */
    protected function restoreNginxBlocks(ScannerState $state, ScanOutput $output): void
    {
        if ($output->nginxDenied === null) {
            return;
        }

        BlockedAddress::query()
            ->where('server_id', $state->server_id)
            ->where('status', ResourceStatus::Installed)
            ->whereNotIn('ip', $output->nginxDenied)
            ->get()
            ->each(fn (BlockedAddress $address) => BlockAddress::dispatch($address));
    }

    /**
     * Where the next scan starts reading each log. A journal that refused its cursor starts again from recent history,
     * and access logs that are gone, such as a removed site's, are forgotten.
     *
     * @return array{journal: string|null, files: array<string, array{inode: int, offset: int}>}
     */
    protected function cursors(ScannerState $state, ScanOutput $output): array
    {
        $journal = match (true) {
            $output->journalFailed => null,
            $output->journalCursor !== null => $output->journalCursor,
            default => $state->cursors['journal'] ?? null,
        };

        $files = [];

        foreach ($output->files as $file) {
            $files[$file->path] = ['inode' => $file->inode, 'offset' => $file->nextOffset()];
        }

        return ['journal' => $journal, 'files' => $files];
    }
}
