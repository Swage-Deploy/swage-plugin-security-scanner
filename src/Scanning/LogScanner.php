<?php

namespace Swage\SecurityScanner\Scanning;

use App\Ssh\RemoteShell;
use RuntimeException;
use Swage\SecurityScanner\Models\ScannerState;

/**
 * Reads what a server's logs gained since the last scan, counts it and raises alerts from it.
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

        $this->recorder->record($state->server, $events);
        $this->detector->detect($state, $events);

        $state->update([
            'cursors' => $this->cursors($state, $output),
            'panel_address' => $panelAddress,
            'fail2ban_installed' => $output->fail2banInstalled,
            'fail2ban_banned' => $output->fail2banBanned,
            'last_scanned_at' => now(),
            'last_error' => null,
        ]);

        return $events;
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
