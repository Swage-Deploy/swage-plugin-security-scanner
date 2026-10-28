<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * What each AI review was sent and checked, and how much of the API it used, so people can confirm a review that
     * found nothing really read the server.
     */
    public function up(): void
    {
        Schema::table('security_scanner_ai_reviews', function (Blueprint $table) {
            $table->json('checked')->nullable()->after('findings');
            $table->json('missing_sections')->nullable()->after('checked');
            $table->longText('input')->nullable()->after('missing_sections');
            $table->string('reported_model')->nullable()->after('model');
            $table->unsignedInteger('input_tokens')->nullable()->after('input');
            $table->unsignedInteger('output_tokens')->nullable()->after('input_tokens');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('security_scanner_ai_reviews', function (Blueprint $table) {
            $table->dropColumn(['checked', 'missing_sections', 'input', 'reported_model', 'input_tokens', 'output_tokens']);
        });
    }
};
