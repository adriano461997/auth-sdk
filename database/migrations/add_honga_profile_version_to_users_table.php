<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            if (! Schema::hasColumn('users', 'honga_profile_version')) {
                $table->unsignedBigInteger('honga_profile_version')->default(0)->after('honga_synced_at');
            }
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            if (Schema::hasColumn('users', 'honga_profile_version')) {
                $table->dropColumn('honga_profile_version');
            }
        });
    }
};
