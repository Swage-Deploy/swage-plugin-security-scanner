<?php

namespace Swage\SecurityScanner\Scanning;

/**
 * What a scan read from a server.
 */
final class ScanOutput
{
    /**
     * The address the server saw Swage connect from, whose own SSH logins are not counted.
     */
    public ?string $clientAddress = null;

    /**
     * @var list<string>
     */
    public array $journalLines = [];

    /**
     * Where the journal was read up to, or null when it had nothing new.
     */
    public ?string $journalCursor = null;

    /**
     * Whether the journal refused to be read, such as when the last cursor was rotated out of it.
     */
    public bool $journalFailed = false;

    public bool $fail2banInstalled = false;

    /**
     * The jails fail2ban runs, or null when it could not say, such as on servers scanned before it was asked.
     *
     * @var list<string>|null
     */
    public ?array $fail2banJails = null;

    /**
     * @var list<string>
     */
    public array $fail2banBanned = [];

    /**
     * Whether fail2ban's jails leave Swage's address alone, or null when fail2ban is not installed.
     */
    public ?bool $fail2banIgnoresPanel = null;

    /**
     * Whether fail2ban's recidive jail reads the log fail2ban writes its bans to, or null when it could not say.
     */
    public ?bool $fail2banRecidiveReadsLog = null;

    /**
     * Whether fail2ban's sshd jail counts failures over at least an hour, or null when it could not say.
     */
    public ?bool $fail2banSshdCountsHour = null;

    /**
     * The addresses in nginx's deny list, or null when the server does not run nginx.
     *
     * @var list<string>|null
     */
    public ?array $nginxDenied = null;

    /**
     * @var list<ScannedFile>
     */
    public array $files = [];
}
