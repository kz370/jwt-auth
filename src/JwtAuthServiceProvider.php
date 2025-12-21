<?php

namespace Kz370\JwtAuth;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use Kz370\JwtAuth\Services\JwtService;
use Kz370\JwtAuth\Services\RefreshTokenService;
use Kz370\JwtAuth\Http\Middleware\JwtAuthenticate;
use Kz370\JwtAuth\Http\Middleware\JwtRefreshToken;
use Kz370\JwtAuth\Console\Commands\JwtSecretCommand;
use Kz370\JwtAuth\Console\Commands\CleanupTokensCommand;
use Kz370\JwtAuth\Guards\JwtGuard;
use Illuminate\Support\Facades\Auth;

class JwtAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/jwt-auth.php',
            'jwt-auth'
        );

        $this->app->singleton(JwtService::class, function ($app) {
            return new JwtService(config('jwt-auth'));
        });

        $this->app->singleton(RefreshTokenService::class, function ($app) {
            return new RefreshTokenService(config('jwt-auth'));
        });

        $this->app->singleton('jwt-auth', function ($app) {
            return new JwtAuthManager(
                $app->make(JwtService::class),
                $app->make(RefreshTokenService::class),
                config('jwt-auth')
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/jwt-auth.php' => config_path('jwt-auth.php'),
        ], 'jwt-auth-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations'),
        ], 'jwt-auth-migrations');

        if ($this->app->runningInConsole()) {
            $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

            $this->commands([
                JwtSecretCommand::class,
                CleanupTokensCommand::class,
            ]);
        }

        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('jwt.auth', JwtAuthenticate::class);
        $router->aliasMiddleware('jwt.refresh', JwtRefreshToken::class);

        $guardName = config('jwt-auth.guard_name', 'jwt');

        // Automatically inject the guard into the auth configuration
        $this->app['config']->set("auth.guards.{$guardName}", [
            'driver' => 'jwt',
            'provider' => 'users',
        ]);

        // Optionally set this as the default guard
        if (config('jwt-auth.override_default_guard', false)) {
            $this->app['config']->set('auth.defaults.guard', $guardName);
        }

        Auth::extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app->make(JwtService::class),
                Auth::createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }
}
