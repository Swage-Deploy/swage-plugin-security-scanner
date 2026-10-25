<?php

namespace Swage\SecurityScanner\Enums;

/**
 * What raised an alert. Each rule raises at most one open alert per address, and counts further occurrences on it.
 *
 * Only SSH logins raise alerts. Brute force attempts and probing are left to fail2ban, which bans the addresses
 * behind them.
 */
enum AlertRule: string
{
    case SshLoginAfterFailures = 'ssh_login_after_failures';
    case SshLoginNewAddress = 'ssh_login_new_address';

    public function title(): string
    {
        return match ($this) {
            self::SshLoginAfterFailures => __('SSH login from an address that was failing to log in'),
            self::SshLoginNewAddress => __('SSH login from a new address'),
        };
    }

    public function severity(): AlertSeverity
    {
        return match ($this) {
            self::SshLoginAfterFailures => AlertSeverity::High,
            self::SshLoginNewAddress => AlertSeverity::Low,
        };
    }
}
