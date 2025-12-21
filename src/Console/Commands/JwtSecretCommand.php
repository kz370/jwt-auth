<?php

namespace Kz370\JwtAuth\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Str;

class JwtSecretCommand extends Command
{
    protected $signature = 'jwt:secret {--force : Overwrite existing key}';
    protected $description = 'Set the JWT Auth secret key';

    public function handle(): void
    {
        $key = Str::random(64);

        if (!$this->setKeyInEnvironmentFile($key)) {
            return;
        }

        $this->laravel['config']['jwt-auth.secret'] = $key;

        $this->info("JWT secret key [$key] set successfully.");
    }

    protected function setKeyInEnvironmentFile(string $key): bool
    {
        $currentKey = $this->laravel['config']['jwt-auth.secret'];

        if (strlen($currentKey) !== 0 && !$this->option('force')) {
            $this->error('JWT secret key already exists. Use --force to overwrite.');
            return false;
        }

        $path = $this->laravel->environmentFilePath();

        if (!file_exists($path)) {
            $this->error('.env file not found.');
            return false;
        }

        $content = file_get_contents($path);

        // If JWT_SECRET exists, replace it, otherwise append it
        if (strpos($content, 'JWT_SECRET=') !== false) {
             $content = preg_replace(
                '/^JWT_SECRET=.*/m',
                'JWT_SECRET=' . $key,
                $content
            );
        } else {
            $content .= PHP_EOL . 'JWT_SECRET=' . $key . PHP_EOL;
        }

        file_put_contents($path, $content);
        return true;
    }
}
