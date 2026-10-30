<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Bans are permanent, so a server can have thousands of them. They move from one list on the scanner's state to a
     * row each, which the panel can page through and leave out of other lists in the database.
     */
    public function up(): void
    {
        Schema::create('security_scanner_fail2ban_bans', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('ip', 64);
            $table->timestamps();

            $table->unique(['server_id', 'ip']);
        });

        $now = now();

        DB::table('security_scanner_states')->whereNotNull('fail2ban_banned')->get(['server_id', 'fail2ban_banned'])
            ->each(function (object $state) use ($now): void {
                $ips = array_values(array_unique(array_filter((array) json_decode((string) $state->fail2ban_banned, true), 'is_string')));

                foreach (array_chunk($ips, 500) as $chunk) {
                    DB::table('security_scanner_fail2ban_bans')->insert(array_map(fn (string $ip): array => ['server_id' => $state->server_id, 'ip' => $ip, 'created_at' => $now, 'updated_at' => $now], $chunk));
                }
            });

        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->dropColumn('fail2ban_banned');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->json('fail2ban_banned')->nullable();
        });

        DB::table('security_scanner_fail2ban_bans')->get(['server_id', 'ip'])->groupBy('server_id')
            ->each(fn ($bans, int $serverId) => DB::table('security_scanner_states')->where('server_id', $serverId)->update(['fail2ban_banned' => json_encode($bans->pluck('ip')->all())]));

        Schema::dropIfExists('security_scanner_fail2ban_bans');
    }
};
