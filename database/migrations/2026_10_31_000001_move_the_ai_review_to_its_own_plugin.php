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
     * The AI review moved to its own plugin, swage/ai-review, which starts afresh: the scanner's reviews, ignored
     * findings, per-server switches and API settings are removed.
     */
    public function up(): void
    {
        Schema::dropIfExists('security_scanner_ignored_findings');
        Schema::dropIfExists('security_scanner_ai_reviews');

        Schema::table('security_scanner_states', function (Blueprint $table) {
            $table->dropColumn(['ai_enabled', 'ai_reviewed_at', 'ai_error']);
        });

        if (Schema::hasTable('plugin_settings')) {
            DB::table('plugin_settings')->where('integration', 'server:security-scanner')->whereIn('key', ['url', 'api_key', 'model'])->delete();
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
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
            $table->string('reported_model')->nullable();
            $table->text('summary');
            $table->json('findings');
            $table->json('checked')->nullable();
            $table->json('missing_sections')->nullable();
            $table->longText('input')->nullable();
            $table->unsignedInteger('input_tokens')->nullable();
            $table->unsignedInteger('output_tokens')->nullable();
            $table->foreignId('requested_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index(['server_id', 'created_at']);
        });

        Schema::create('security_scanner_ignored_findings', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('key', 80);
            $table->string('title');
            $table->foreignId('ignored_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->unique(['server_id', 'key']);
        });
    }
};
