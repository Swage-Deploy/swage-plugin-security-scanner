<?php

return [
    // How often, in minutes, each server's logs are read.
    'interval' => (int) env('SECURITY_SCANNER_INTERVAL', 2),

    // How many days of counted events are kept. Alerts are kept until 90 days after they are resolved.
    'retention_days' => (int) env('SECURITY_SCANNER_RETENTION_DAYS', 14),

    // How many failed SSH logins, and how many probes for vulnerable files, from one address within a day make fail2ban
    // ban it for good. Servers pick up a change when fail2ban is installed or updated from the panel.
    'fail2ban_ssh' => (int) env('SECURITY_SCANNER_SSH_FAILURES', 10),
    'fail2ban_probes' => (int) env('SECURITY_SCANNER_HTTP_PROBES', 5),

    // Requests for paths matching these patterns are counted as probing. No visitor asks a Laravel site for dotfiles,
    // dependencies or well known admin tools, so these are scanners.
    'probes' => [
        '~/\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|DS_Store|htpasswd|htaccess|npmrc)~i',
        '~/node_modules/~i',
        '~/wp-(admin|login|content|includes|config)~i',
        '~/xmlrpc\.php~i',
        '~/(phpmyadmin|pma|myadmin|adminer|phpinfo)~i',
        '~/vendor/phpunit~i',
        '~eval-stdin\.php~i',
        '~/(cgi-bin|boaform|HNAP1|actuator|solr|server-status|_ignition)~i',
        '~(\.\./|%2e%2e)~i',
        '~/etc/(passwd|shadow)~i',
    ],

    // Requests for paths matching these patterns are only counted as probing when they fail with a 403 or 404. Scanners
    // guess at backups and PHP scripts that aren't there, but a site can serve real downloads or an old script, and
    // visitors to those shouldn't be banned. They can't match a space or quote, so fail2ban matches them the same way.
    'probes_when_failed' => [
        '~\.(sql|bak|old|swp|tar|gz|zip|7z|rar)(?=[?\s"]|$)~i',
        '~/(?!index\.php)[^/?\s"]+\.php~i',
    ],
];
