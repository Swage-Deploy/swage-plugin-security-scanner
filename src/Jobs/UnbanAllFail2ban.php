<?php

namespace Swage\SecurityScanner\Jobs;

use App\Actions\Servers\RunServerTask;
use App\Models\Server;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Swage\SecurityScanner\Models\Fail2banBan;

/**
 * Lifts every ban fail2ban holds on the server, in every jail, so the list doesn't keep growing now bans are permanent.
 *
 * fail2ban is stopped, its saved bans are deleted from its database and it is started again, rather than unbanning
 * addresses one at a time, which would reload nginx once for each of them. Stopping it empties its firewall rules and
 * nginx deny files. The failures it had counted are forgotten, but it carries on reading the logs where it stopped.
 * Addresses blocked from the panel stay blocked.
 */
class UnbanAllFail2ban implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    /**
     * Where fail2ban keeps its bans, unless its config says otherwise.
     */
    public const string DATABASE = '/var/lib/fail2ban/fail2ban.sqlite3';

    public int $timeout = 120;

    public int $tries = 1;

    public function __construct(public Server $server) {}

    public function uniqueId(): string
    {
        return (string) $this->server->id;
    }

    /**
     * Execute the job.
     */
    public function handle(RunServerTask $runTask): void
    {
        $database = self::DATABASE;

        $runTask->run($this->server, 'Lifting every fail2ban ban', <<<BASH
        set -Eeuo pipefail

        systemctl stop fail2ban
        trap 'systemctl start fail2ban' EXIT

        # fail2ban needs Python, so it's there to clear the bans it restores on start.
        python3 - {$database} <<'PY'
        import sqlite3, sys

        db = sqlite3.connect(sys.argv[1])
        for table in ('bans', 'bips'):
            try:
                db.execute(f'DELETE FROM {table}')
            except sqlite3.OperationalError:
                pass
        db.commit()
        PY

        if command -v nginx > /dev/null 2>&1; then
            for file in /etc/nginx/conf.d/swage-fail2ban-*.conf; do
                [ -f "\$file" ] && : > "\$file"
            done
            nginx -t -q && systemctl reload nginx
        fi

        echo "fail2ban's bans are lifted."
        BASH);

        Fail2banBan::query()->where('server_id', $this->server->id)->delete();
    }
}
