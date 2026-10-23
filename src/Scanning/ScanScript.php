<?php

namespace Swage\SecurityScanner\Scanning;

use Illuminate\Support\Str;

/**
 * The script that reads what a server's logs gained since the last scan, and the reading of its output.
 *
 * SSH and sudo are read from the systemd journal after the cursor the last scan stopped at. nginx's access logs are
 * read from the byte offset the last scan stopped at, starting again from the top when a log's inode changes, which
 * is how logrotate leaves it. Logs seen for the first time are only read back a little way.
 *
 * Log lines hold text attackers choose, such as request paths and usernames, so each section of the output starts
 * with a marker made fresh for every scan, which no log line can know in advance.
 */
final readonly class ScanScript
{
    /**
     * How far back a log seen for the first time is read.
     */
    public const int BACKFILL_BYTES = 262144;

    /**
     * The most of one access log read in a scan. A log that grew by more is caught up over the following scans.
     */
    public const int MAX_BYTES_PER_FILE = 2097152;

    /**
     * The most journal lines read in a scan, keeping the newest.
     */
    public const int MAX_JOURNAL_LINES = 20000;

    /**
     * How far back the journal is read on the first scan, or when the last cursor is no longer in the journal.
     */
    public const string JOURNAL_SINCE = '-15 min';

    public function __construct(public string $marker) {}

    public static function make(): self
    {
        return new self('@@SWAGE_SCAN_'.Str::upper(Str::random(24)));
    }

    /**
     * @param  array{journal?: string|null, files?: array<string, array{inode: int, offset: int}>}  $cursors
     */
    public function render(array $cursors): string
    {
        $marker = escapeshellarg($this->marker);
        $journal = filled($cursors['journal'] ?? null) ? '--after-cursor='.escapeshellarg($cursors['journal']) : '--since='.escapeshellarg(self::JOURNAL_SINCE);

        $known = collect($cursors['files'] ?? [])
            ->filter(fn (mixed $cursor, string $path): bool => str_starts_with($path, '/var/log/nginx/') && is_array($cursor))
            ->map(fn (array $cursor, string $path): string => '['.escapeshellarg($path).']='.escapeshellarg((int) $cursor['inode'].':'.(int) $cursor['offset']))
            ->implode(' ');

        $backfill = self::BACKFILL_BYTES;
        $maxBytes = self::MAX_BYTES_PER_FILE;
        $maxLines = self::MAX_JOURNAL_LINES;

        return <<<BASH
        set -uo pipefail
        marker={$marker}
        section() { printf '\\n%s %s\\n' "\$marker" "\$*"; }

        client=\${SSH_CLIENT:-}
        section client "\${client%% *}"

        section journal
        if out=\$(journalctl --no-pager -o short-iso --show-cursor {$journal} SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session SYSLOG_IDENTIFIER=sudo 2>/dev/null); then
            printf '%s\\n' "\$out" | tail -n {$maxLines}
        else
            section journal-failed
        fi

        section fail2ban
        if command -v fail2ban-client > /dev/null 2>&1; then
            echo installed
            fail2ban-client status sshd 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p'
        fi

        declare -A known=({$known})
        for f in /var/log/nginx/*access.log; do
            [ -f "\$f" ] || continue
            read -r inode size < <(stat -c '%i %s' -- "\$f")
            entry=\${known["\$f"]:-}
            if [ -z "\$entry" ]; then
                start=\$(( size > {$backfill} ? size - {$backfill} : 0 ))
            elif [ "\${entry%%:*}" = "\$inode" ] && [ "\${entry#*:}" -le "\$size" ]; then
                start=\${entry#*:}
            else
                start=0
            fi
            length=\$(( size - start ))
            [ "\$length" -gt {$maxBytes} ] && length={$maxBytes}
            section nginx "\$inode" "\$start" "\$([ -z "\$entry" ] && echo new || echo known)" "\$f"
            tail -c +\$(( start + 1 )) -- "\$f" | head -c "\$length"
        done

        section end
        BASH;
    }

    /**
     * Read the script's output into the sections each log wrote.
     */
    public function parse(string $output): ScanOutput
    {
        $result = new ScanOutput;

        foreach (array_slice(explode("\n{$this->marker} ", "\n".$output), 1) as $section) {
            [$header, $content] = array_pad(explode("\n", $section, 2), 2, '');
            $fields = explode(' ', $header, 5);

            match ($fields[0]) {
                'client' => $result->clientAddress = filter_var(trim($fields[1] ?? ''), FILTER_VALIDATE_IP) ?: null,
                'journal' => $this->readJournal($result, $content),
                'journal-failed' => $result->journalFailed = true,
                'fail2ban' => $this->readFail2ban($result, $content),
                'nginx' => count($fields) === 5 ? $result->files[] = new ScannedFile(
                    path: $fields[4],
                    inode: (int) $fields[1],
                    start: (int) $fields[2],
                    isNew: $fields[3] === 'new',
                    content: $content,
                ) : null,
                default => null,
            };
        }

        return $result;
    }

    protected function readJournal(ScanOutput $result, string $content): void
    {
        foreach (explode("\n", $content) as $line) {
            if (str_starts_with($line, '-- cursor: ')) {
                $result->journalCursor = trim(substr($line, strlen('-- cursor: ')));
            } elseif ($line !== '' && ! str_starts_with($line, '-- ')) {
                $result->journalLines[] = $line;
            }
        }
    }

    protected function readFail2ban(ScanOutput $result, string $content): void
    {
        $lines = explode("\n", trim($content), 2);

        if ($lines[0] !== 'installed') {
            $result->fail2banInstalled = false;

            return;
        }

        $result->fail2banInstalled = true;
        $result->fail2banBanned = array_values(array_filter(
            preg_split('/[\s,]+/', $lines[1] ?? '', flags: PREG_SPLIT_NO_EMPTY) ?: [],
            fn (string $ip): bool => filter_var($ip, FILTER_VALIDATE_IP) !== false,
        ));
    }
}
