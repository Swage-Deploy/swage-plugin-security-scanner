<?php

return [
    // How often, in minutes, each server's logs are read.
    'interval' => (int) env('SECURITY_SCANNER_INTERVAL', 2),

    // How many days of counted events are kept. Alerts are kept until 90 days after they are resolved.
    'retention_days' => (int) env('SECURITY_SCANNER_RETENTION_DAYS', 14),

    // How many probes from one address within an hour make fail2ban ban it from the sites. Servers pick up a change
    // when fail2ban is installed or updated from the panel.
    'fail2ban_probes' => (int) env('SECURITY_SCANNER_HTTP_PROBES', 20),

    // Requests for paths matching these patterns are counted as probing. Laravel sites only serve index.php, so
    // requests for other PHP scripts, dotfiles and well known admin tools are almost always scanners.
    'probes' => [
        '~/\.(env|git|svn|hg|aws|ssh|docker|vscode|idea|DS_Store|htpasswd|htaccess)~i',
        '~/wp-(admin|login|content|includes|config)~i',
        '~/xmlrpc\.php~i',
        '~/(phpmyadmin|pma|myadmin|adminer|phpinfo)~i',
        '~/vendor/phpunit~i',
        '~eval-stdin\.php~i',
        '~/(cgi-bin|boaform|HNAP1|actuator|solr|server-status|_ignition)~i',
        '~(\.\./|%2e%2e)~i',
        '~/etc/(passwd|shadow)~i',
        '~\.(sql|bak|old|swp|tar|gz|zip|7z|rar)(\?|$)~i',
        '~/(?!index\.php)[^/?]+\.php~i',
    ],
];
