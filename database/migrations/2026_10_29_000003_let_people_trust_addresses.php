<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * The addresses and ranges people trust on each server, which are never counted, alerted on, blocked or banned.
     */
    public function up(): void
    {
        Schema::create('security_scanner_trusted_addresses', function (Blueprint $table) {
            $table->id();
            $table->foreignId('server_id')->constrained()->cascadeOnDelete();
            $table->string('ip', 64);
            $table->string('note')->nullable();
            $table->foreignId('trusted_by_id')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->unique(['server_id', 'ip']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_scanner_trusted_addresses');
    }
};
