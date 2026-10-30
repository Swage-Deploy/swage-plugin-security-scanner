<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->boolean('fail2ban_bans_permanently')->nullable()->after('fail2ban_sshd_counts_hour');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->dropColumn('fail2ban_bans_permanently');
        });
    }
};
