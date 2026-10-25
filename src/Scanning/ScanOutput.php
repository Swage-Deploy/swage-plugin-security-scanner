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
     * @var list<string>
     */
    public array $fail2banBanned = [];

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
