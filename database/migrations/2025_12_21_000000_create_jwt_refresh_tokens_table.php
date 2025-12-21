<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $tableName = config('jwt-auth.table_name', 'jwt_refresh_tokens');

        if (!Schema::hasTable($tableName)) {
            Schema::create($tableName, function (Blueprint $table) {
                $table->id();
                $table->unsignedBigInteger('authenticatable_id');
                $table->string('authenticatable_type');

                $table->string('token_hash', 64)->unique();
                $table->string('family_id', 64)->index();
                $table->string('device_name')->nullable();
                $table->string('ip_address', 45)->nullable();
                $table->text('user_agent')->nullable();
                $table->timestamp('expires_at');
                $table->timestamp('used_at')->nullable();
                $table->boolean('is_revoked')->default(false);
                $table->timestamps();

                $table->index(['authenticatable_id', 'authenticatable_type'], 'jwt_tokens_user_index');
                $table->index(['family_id', 'is_revoked']);
            });
        }
    }

    public function down(): void
    {
        $tableName = config('jwt-auth.table_name', 'jwt_refresh_tokens');
        Schema::dropIfExists($tableName);
    }
};
