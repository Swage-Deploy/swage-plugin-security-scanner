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
        Schema::create('security_scanner_states', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->unique()->constrained()->cascadeOnDelete();
            $table->boolean('enabled')->default(false);
            $table->json('cursors')->nullable();
            $table->string('panel_address', 45)->nullable();
            $table->boolean('fail2ban_installed')->nullable();
            $table->json('fail2ban_banned')->nullable();
            $table->timestamp('last_scanned_at')->nullable();
            $table->text('last_error')->nullable();
            $table->timestamps();
        });

        Schema::create('security_scanner_events', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('kind');
            $table->string('ip', 45)->nullable();
            $table->string('source');
            $table->timestamp('bucket');
            $table->unsignedInteger('count')->default(0);
            $table->json('targets')->nullable();
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamps();

            $table->index(['server_id', 'kind', 'bucket']);
            $table->index(['server_id', 'ip']);
        });

        Schema::create('security_scanner_alerts', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('rule');
            $table->string('severity');
            $table->string('subject');
            $table->json('details')->nullable();
            $table->unsignedInteger('occurrences')->default(1);
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamp('resolved_at')->nullable();
            $table->foreignId('resolved_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['server_id', 'resolved_at']);
        });

        Schema::create('security_scanner_blocked_addresses', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('ip', 45);
            $table->string('reason')->nullable();
            $table->string('status');
            $table->foreignId('blocked_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->unique(['server_id', 'ip']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_scanner_blocked_addresses');
        Schema::dropIfExists('security_scanner_alerts');
        Schema::dropIfExists('security_scanner_events');
        Schema::dropIfExists('security_scanner_states');
    }
};
