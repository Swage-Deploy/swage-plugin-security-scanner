<?php

namespace Swage\SecurityScanner\Models;

use App\Models\Server;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Swage\SecurityScanner\Jobs\InstallFail2ban;

/**
 * Whether a server's logs are scanned, and where the last scan stopped reading each of them.
 *
 * @property array{journal?: string|null, files?: array<string, array{inode: int, offset: int}>}|null $cursors
 */
#[Table('security_scanner_states')]
#[Fillable(['server_id', 'enabled', 'cursors', 'panel_address', 'fail2ban_installed', 'fail2ban_jails', 'fail2ban_ignores_panel', 'fail2ban_banned', 'last_scanned_at', 'last_error', 'ai_enabled', 'ai_reviewed_at', 'ai_error'])]
class ScannerState extends Model
{
    /**
     * The model's default values for attributes.
     *
     * @var array<string, mixed>
     */
    protected $attributes = [
        'enabled' => false,
        'ai_enabled' => false,
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'enabled' => 'boolean',
            'cursors' => 'array',
            'fail2ban_installed' => 'boolean',
            'fail2ban_jails' => 'array',
            'fail2ban_ignores_panel' => 'boolean',
            'fail2ban_banned' => 'array',
            'last_scanned_at' => 'datetime',
            'ai_enabled' => 'boolean',
            'ai_reviewed_at' => 'datetime',
        ];
    }

    public static function for(Server $server): self
    {
        return static::firstOrCreate(['server_id' => $server->id]);
    }

    /**
     * @return BelongsTo<Server, $this>
     */
    public function server(): BelongsTo
    {
        return $this->belongsTo(Server::class);
    }

    /**
     * Determine if the server has been scanned before, so its logs have a starting point. The first scan only reads
     * recent history, and logins it finds become the addresses the server is known to be reached from.
     */
    public function hasBaseline(): bool
    {
        return $this->last_scanned_at !== null;
    }

    /**
     * Determine if fail2ban needs updating, because it could ban Swage's own address or does not ban probing yet.
     */
    public function needsFail2banUpdate(): bool
    {
        return $this->fail2banCanBanPanel() || $this->fail2banMissesProbes();
    }

    /**
     * Determine if fail2ban was installed before its jails left Swage's address alone, so failed logins or probes from
     * it could lock Swage out of the server. Servers not scanned since this was checked can't tell.
     */
    public function fail2banCanBanPanel(): bool
    {
        return $this->fail2ban_installed && $this->fail2ban_ignores_panel === false;
    }

    /**
     * Determine if fail2ban was installed before it banned addresses probing sites. Servers without nginx have no
     * probes jail, and servers not scanned since this was checked can't tell.
     */
    public function fail2banMissesProbes(): bool
    {
        return $this->fail2ban_installed
            && $this->fail2ban_jails !== null
            && ! in_array(InstallFail2ban::PROBES_JAIL, $this->fail2ban_jails, true)
            && collect($this->cursors['files'] ?? [])->isNotEmpty();
    }
}
