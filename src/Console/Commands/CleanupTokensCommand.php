<?php

namespace Kz370\JwtAuth\Console\Commands;

use Illuminate\Console\Command;
use Kz370\JwtAuth\Services\RefreshTokenService;

class CleanupTokensCommand extends Command
{
    protected $signature = 'jwt:cleanup';
    protected $description = 'Clean up expired refresh tokens from the database';

    public function handle(RefreshTokenService $service): void
    {
        $count = $service->cleanupExpired();
        $this->info("Cleaned up {$count} expired or revoked refresh tokens.");
    }
}
