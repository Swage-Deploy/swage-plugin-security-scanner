<?php

namespace Swage\SecurityScanner\Enums;

/**
 * What raised an alert. Each rule raises at most one open alert per subject, an address or a user, and counts
 * further occurrences on it.
 */
enum AlertRule: string
{
    case SshBruteForce = 'ssh_brute_force';
    case SshLoginAfterFailures = 'ssh_login_after_failures';
    case SshLoginNewAddress = 'ssh_login_new_address';
    case SudoFailure = 'sudo_failure';
    case HttpProbing = 'http_probing';
    case HttpLoginBruteForce = 'http_login_brute_force';

    public function title(): string
    {
        return match ($this) {
            self::SshBruteForce => __('Repeated SSH login attempts'),
            self::SshLoginAfterFailures => __('SSH login from an address that was failing to log in'),
            self::SshLoginNewAddress => __('SSH login from a new address'),
            self::SudoFailure => __('Failed sudo attempts'),
            self::HttpProbing => __('Probing for vulnerable files'),
            self::HttpLoginBruteForce => __('Repeated login attempts on a site'),
        };
    }

    public function severity(): AlertSeverity
    {
        return match ($this) {
            self::SshLoginAfterFailures => AlertSeverity::High,
            self::SshBruteForce, self::SudoFailure, self::HttpLoginBruteForce => AlertSeverity::Medium,
            self::SshLoginNewAddress, self::HttpProbing => AlertSeverity::Low,
        };
    }

    /**
     * Determine if the alert's subject is an address that can be blocked, rather than a user.
     */
    public function concernsAddress(): bool
    {
        return $this !== self::SudoFailure;
    }
}
