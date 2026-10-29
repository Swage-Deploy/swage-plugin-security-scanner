<?php

namespace Swage\SecurityScanner\Ai;

use Illuminate\Support\Str;

/**
 * The script that reads how a server is set up, for the AI review: its SSH settings, open ports, firewall rules,
 * pending updates, accounts and failed services.
 *
 * It only reads. The AI never writes it or adds to it, and it never writes a file, changes a setting or restarts
 * anything, so the review cannot change the server. Keep it that way: tests check the script against the commands it
 * is allowed to run.
 *
 * Its output holds text others can choose, such as account names, so each section starts with a marker made fresh for
 * every run, which nothing on the server can know in advance.
 */
final readonly class PostureScript
{
    /**
     * The most of each section's output kept, so one noisy command can't crowd out the rest of the review.
     */
    public const int MAX_SECTION_BYTES = 6000;

    /**
     * The sections the script writes, and what each is called in the review.
     *
     * @var array<string, string>
     */
    public const array SECTIONS = [
        'os' => 'Operating system and kernel',
        'reboot-required' => 'Reboot required by updates',
        'updates' => 'Packages with pending updates',
        'auto-updates' => 'Automatic security updates',
        'sshd' => 'Effective SSH server settings',
        'listening' => 'Listening ports',
        'firewall' => 'Firewall (ufw) status',
        'accounts' => 'Accounts that can log in, and root equivalents',
        'passwords' => 'Accounts with a usable password',
        'authorized-keys' => 'Authorized SSH keys per account',
        'sudo' => 'Passwordless sudo rules',
        'failed-units' => 'Failed systemd units',
        'logins' => 'Recent logins',
    ];

    public function __construct(public string $marker) {}

    public static function make(): self
    {
        return new self('@@SWAGE_POSTURE_'.Str::upper(Str::random(24)));
    }

    public function render(): string
    {
        $marker = escapeshellarg($this->marker);

        return <<<BASH
        set -uo pipefail
        marker={$marker}
        section() { printf '\\n%s %s\\n' "\$marker" "\$*"; }

        # Sections say "unavailable" when their command failed or isn't installed, and "none" when it ran and found
        # nothing, so the review can tell a clean server from one it couldn't read.
        or_none() { local out; out=\$(cat); if [ -n "\$out" ]; then printf '%s\\n' "\$out"; else echo none; fi; }

        section os
        { sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"'; uname -r; uptime -p 2>/dev/null; } | or_none

        section reboot-required
        if [ -f /var/run/reboot-required ]; then echo yes; cat /var/run/reboot-required.pkgs 2>/dev/null; else echo no; fi

        section updates
        if out=\$(apt list --upgradable 2>/dev/null); then printf '%s\\n' "\$out" | grep -v '^Listing' | head -n 200 | or_none; else echo unavailable; fi

        section auto-updates
        if command -v systemctl > /dev/null; then
            echo "unattended-upgrades \$(systemctl is-enabled unattended-upgrades 2>/dev/null || echo not-installed)"
            cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null
        else
            echo unavailable
        fi

        section sshd
        if out=\$(sshd -T 2>/dev/null); then
            printf '%s\\n' "\$out" | grep -Ei '^(port|listenaddress|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitemptypasswords|authenticationmethods|maxauthtries|logingracetime|x11forwarding|allowtcpforwarding|allowagentforwarding|permittunnel|allowusers|allowgroups|denyusers|denygroups|clientaliveinterval|clientalivecountmax) ' | or_none
        else
            echo unavailable
        fi

        section listening
        if out=\$(ss -H -tulpn 2>/dev/null); then printf '%s\\n' "\$out" | awk '{print \$1, \$5, \$7}' | or_none; else echo unavailable; fi

        section firewall
        if ! command -v ufw > /dev/null; then echo 'not installed'; elif out=\$(ufw status verbose 2>/dev/null); then printf '%s\\n' "\$out" | or_none; else echo unavailable; fi

        section accounts
        awk -F: '\$3 == 0 || (\$3 >= 1000 && \$7 !~ /(nologin|false)\$/) { print \$1, "uid=" \$3, \$7 }' /etc/passwd | or_none

        # Only account names are printed, never the password hashes.
        section passwords
        if out=\$(awk -F: '\$2 == "" { print \$1, "empty password" } \$2 != "" && \$2 !~ /^[!*]/ { print \$1, "password set" }' /etc/shadow 2>/dev/null); then printf '%s\\n' "\$out" | or_none; else echo unavailable; fi

        section authorized-keys
        while IFS=: read -r name _ uid _ _ home _; do
            f="\$home/.ssh/authorized_keys"
            [ -f "\$f" ] && echo "\$name \$(grep -cvE '^[[:space:]]*(#|\$)' "\$f" 2>/dev/null) keys"
        done < /etc/passwd | or_none

        section sudo
        grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n 50 | or_none

        section failed-units
        if command -v systemctl > /dev/null; then systemctl --failed --no-legend --plain 2>/dev/null | head -n 50 | or_none; else echo unavailable; fi

        section logins
        if command -v last > /dev/null; then last -n 20 -i -w 2>/dev/null | grep -vE '^(\$|wtmp)' | or_none; else echo unavailable; fi

        section end
        BASH;
    }

    /**
     * The sections a snapshot lacks, or whose command failed or isn't installed, so the review could not see them.
     *
     * @param  array<string, string>  $sections
     * @return list<string>
     */
    public static function missing(array $sections): array
    {
        return array_values(array_filter(
            array_keys(self::SECTIONS),
            fn (string $section): bool => in_array(trim($sections[$section] ?? ''), ['', 'unavailable'], true),
        ));
    }

    /**
     * Read the script's output into its sections, keyed by the names in SECTIONS.
     *
     * @return array<string, string>
     */
    public function parse(string $output): array
    {
        $sections = [];

        foreach (array_slice(explode("\n{$this->marker} ", "\n".$output), 1) as $section) {
            [$name, $content] = array_pad(explode("\n", $section, 2), 2, '');

            if (array_key_exists($name = trim($name), self::SECTIONS)) {
                $sections[$name] = mb_strcut(trim($content), 0, self::MAX_SECTION_BYTES);
            }
        }

        return $sections;
    }
}
