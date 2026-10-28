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
            $table->boolean('ai_enabled')->default(false)->after('last_error');
            $table->timestamp('ai_reviewed_at')->nullable()->after('ai_enabled');
            $table->text('ai_error')->nullable()->after('ai_reviewed_at');
        });

        Schema::create('security_scanner_ai_reviews', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('model');
            $table->text('summary');
            $table->json('findings');
            $table->foreignId('requested_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['server_id', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_scanner_ai_reviews');

        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->dropColumn(['ai_enabled', 'ai_reviewed_at', 'ai_error']);
        });
    }
};
