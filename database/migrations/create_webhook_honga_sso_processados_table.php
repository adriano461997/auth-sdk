<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('webhook_honga_sso_processados')) {
            return;
        }

        Schema::create('webhook_honga_sso_processados', function (Blueprint $table) {
            $table->char('event_id', 36)->primary();
            $table->string('event_type', 50);
            $table->unsignedBigInteger('honga_user_id')->nullable()->index();
            $table->timestamp('processed_at')->useCurrent();

            $table->index(['event_type', 'processed_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('webhook_honga_sso_processados');
    }
};
