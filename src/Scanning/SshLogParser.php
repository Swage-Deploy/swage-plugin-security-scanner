<?php

namespace Swage\SecurityScanner\Scanning;

use Carbon\CarbonImmutable;
use Swage\SecurityScanner\Enums\EventKind;
use Throwable;

/**
 * Reads sshd's and sudo's journal lines, printed by journalctl in its short-iso format.
 *
 * Servers that only accept keys log attempts with a password as a closed connection rather than a failed password,
 * so both count as failed logins.
 */
class SshLogParser
{
    protected const string IP = '(?<ip>[0-9a-fA-F:.]+)';

    /**
     * @param  list<string>  $lines
     * @param  string|null  $ignoreAddress  The address Swage connects from, whose own logins are not counted.
     * @return list<LogEvent>
     */
    public function parse(array $lines, ?string $ignoreAddress = null): array
    {
        $events = [];

        foreach ($lines as $line) {
            if (! preg_match('/^(?<time>\S+) \S+ (?<program>sshd|sshd-session|sudo)(?:\[\d+\])?: (?<message>.*)$/', $line, $matches)) {
                continue;
            }

            try {
                $time = CarbonImmutable::parse($matches['time']);
            } catch (Throwable) {
                continue;
            }

            $event = $matches['program'] === 'sudo'
                ? $this->sudo($matches['message'], $time)
                : $this->sshd($matches['message'], $time);

            if ($event && ($event->ip === null || $event->ip !== $ignoreAddress)) {
                $events[] = $event;
            }
        }

        return $events;
    }

    protected function sshd(string $message, CarbonImmutable $time): ?LogEvent
    {
        $ip = self::IP;

        $patterns = [
            EventKind::SshInvalidUser->value => "/^Invalid user (?<user>\S*) from {$ip} port/",
            EventKind::SshLogin->value => "/^Accepted \S+ for (?<user>\S+) from {$ip} port/",
            EventKind::SshFailedLogin->value => [
                "/^Failed \S+ for (?!invalid user )(?<user>\S+) from {$ip} port/",
                "/^error: maximum authentication attempts exceeded for (?!invalid user )(?<user>\S+) from {$ip} port/",
                "/^Connection closed by authenticating user (?<user>\S+) {$ip} port/",
            ],
        ];

        foreach ($patterns as $kind => $kindPatterns) {
            foreach ((array) $kindPatterns as $pattern) {
                if (preg_match($pattern, $message, $matches) && filter_var($matches['ip'], FILTER_VALIDATE_IP)) {
                    return new LogEvent(EventKind::from($kind), $time, $matches['ip'], 'ssh', $matches['user']);
                }
            }
        }

        return null;
    }

    /**
     * Swage runs scripts as root and switches to other users with sudo, so only sudo used by other users is counted.
     */
    protected function sudo(string $message, CarbonImmutable $time): ?LogEvent
    {
        if (preg_match('/^\s*(?<user>\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers|a password is required) ;/', $message, $matches)) {
            return new LogEvent(EventKind::SudoFailed, $time, null, 'sudo', $matches['user']);
        }

        if (preg_match('/^\s*(?<user>\S+) : .*COMMAND=(?<command>.*)$/', $message, $matches) && $matches['user'] !== 'root') {
            return new LogEvent(EventKind::SudoCommand, $time, null, 'sudo', $matches['user']);
        }

        return null;
    }
}
