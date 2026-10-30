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
     * Marks the address Swage connects to each server from, which is always trusted and can't be removed, and trusts
     * the address scans have already seen.
     */
    public function up(): void
    {
        Schema::table('security_scanner_trusted_addresses', function (Blueprint $table) {
            $table->boolean('swage_host')->default(false)->after('note');
        });

        $now = now();

        DB::table('security_scanner_states')->whereNotNull('panel_address')->get(['server_id', 'panel_address'])
            ->each(function (object $state) use ($now): void {
                if (! filter_var($state->panel_address, FILTER_VALIDATE_IP)) {
                    return;
                }

                $ip = (string) inet_ntop((string) inet_pton($state->panel_address));
                $existing = DB::table('security_scanner_trusted_addresses')->where('server_id', $state->server_id)->where('ip', $ip);

                if ($existing->exists()) {
                    $existing->update(['swage_host' => true]);
                } else {
                    DB::table('security_scanner_trusted_addresses')->insert(['server_id' => $state->server_id, 'ip' => $ip, 'swage_host' => true, 'created_at' => $now, 'updated_at' => $now]);
                }
            });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        DB::table('security_scanner_trusted_addresses')->where('swage_host', true)->whereNull('trusted_by_id')->delete();

        Schema::table('security_scanner_trusted_addresses', function (Blueprint $table) {
            $table->dropColumn('swage_host');
        });
    }
};
