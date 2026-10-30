<?php

namespace Swage\SecurityScanner\Enums;

/**
 * Something worth counting that a server's logs recorded.
 */
enum EventKind: string
{
    case SshFailedLogin = 'ssh_failed_login';
    case SshInvalidUser = 'ssh_invalid_user';
    case SshLogin = 'ssh_login';
    case SudoCommand = 'sudo_command';
    case SudoFailed = 'sudo_failed';
    case HttpProbe = 'http_probe';
    case HttpLogin = 'http_login';
    case HttpDenied = 'http_denied';
    case HttpNotFound = 'http_not_found';

    public function label(): string
    {
        return match ($this) {
            self::SshFailedLogin => __('Failed SSH logins'),
            self::SshInvalidUser => __('Failed SSH logins as accounts that don\'t exist'),
            self::SshLogin => __('SSH logins'),
            self::SudoCommand => __('sudo commands'),
            self::SudoFailed => __('Failed sudo attempts'),
            self::HttpProbe => __('Probes for vulnerable files'),
            self::HttpLogin => __('Login form submissions'),
            self::HttpDenied => __('Denied requests (401/403)'),
            self::HttpNotFound => __('Not found (404)'),
        };
    }

    /**
     * The kinds counted as attempts to get into the server over SSH.
     *
     * @return list<self>
     */
    public static function sshAttempts(): array
    {
        return [self::SshFailedLogin, self::SshInvalidUser];
    }

    /**
     * The kinds that point to an address attacking the server, which the busiest addresses are ranked by.
     *
     * @return list<self>
     */
    public static function hostile(): array
    {
        return [self::SshFailedLogin, self::SshInvalidUser, self::SudoFailed, self::HttpProbe, self::HttpLogin, self::HttpDenied];
    }
}
