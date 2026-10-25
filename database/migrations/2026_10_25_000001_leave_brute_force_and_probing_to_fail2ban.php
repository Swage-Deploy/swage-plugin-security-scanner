<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->json('fail2ban_jails')->nullable()->after('fail2ban_installed');
        });

        // Brute force, probing and sudo alerts are no longer raised. fail2ban bans the addresses behind them instead.
        DB::table('security_scanner_alerts')
            ->whereNotIn('rule', ['ssh_login_after_failures', 'ssh_login_new_address'])
            ->delete();
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->dropColumn('fail2ban_jails');
        });
    }
};
