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
        Schema::table('users', function (Blueprint $table) {
            if (! Schema::hasColumn('users', 'honga_user_id')) {
                $table->unsignedBigInteger('honga_user_id')->nullable()->after('id');
                $table->unique('honga_user_id');
                $table->index('honga_user_id');
            }

            if (! Schema::hasColumn('users', 'honga_synced_at')) {
                $table->timestamp('honga_synced_at')->nullable();
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            if (Schema::hasColumn('users', 'honga_user_id')) {
                $table->dropIndex(['honga_user_id']);
                $table->dropUnique(['honga_user_id']);
                $table->dropColumn('honga_user_id');
            }

            if (Schema::hasColumn('users', 'honga_synced_at')) {
                $table->dropColumn('honga_synced_at');
            }
        });
    }
};
