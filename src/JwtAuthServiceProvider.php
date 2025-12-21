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
            return new JwtService($app['config']->get('jwt-auth'));
        });

        $this->app->singleton(RefreshTokenService::class, function ($app) {
            return new RefreshTokenService($app['config']->get('jwt-auth'));
        });

        $this->app->singleton('jwt-auth', function ($app) {
            return new JwtAuthManager(
                $app->make(JwtService::class),
                $app->make(RefreshTokenService::class),
                $app['config']->get('jwt-auth'),
                $app['request']
            );
        });

        // Register the guard configuration into auth.guards early
        $this->registerGuardInAuth();
    }

    protected function registerGuardInAuth(): void
    {
        $config = $this->app['config'];
        $guardName = $config->get('jwt-auth.guard_name', 'jwt');

        $guards = $config->get('auth.guards', []);

        if (!isset($guards[$guardName])) {
            $config->set("auth.guards.{$guardName}", [
                'driver' => 'jwt',
                'provider' => 'users',
            ]);
        }
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

        $this->app->refresh('request', $this->app->make('jwt-auth'), 'setRequest');

        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('jwt.auth', JwtAuthenticate::class);
        $router->aliasMiddleware('jwt.refresh', JwtRefreshToken::class);

        // Define the 'jwt' driver for the Auth system
        Auth::extend('jwt', function ($app, $name, array $config) {
            $guard = new JwtGuard(
                $app->make(JwtService::class),
                Auth::createUserProvider($config['provider']),
                $app['request']
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });

        // FORCE default guard override if requested
        $pkgConfig = $this->app['config']->get('jwt-auth');
        if (isset($pkgConfig['override_default_guard']) && $pkgConfig['override_default_guard'] === true) {
            $guardName = $pkgConfig['guard_name'] ?? 'jwt';

            // 1. Tell the AuthManager to use this guard as default for this request
            Auth::shouldUse($guardName);

            // 2. Update the config for components that read it directly
            $this->app['config']->set('auth.defaults.guard', $guardName);
        }
    }
}
