<?php

namespace HongaYetu\AuthSDK;

use HongaYetu\AuthSDK\Console\InstallCommand;
use HongaYetu\AuthSDK\Http\Middleware\HongaAuthMiddleware;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class HongaAuthServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/honga-auth.php',
            'honga-auth'
        );

        $this->app->singleton(HongaAuthClient::class, function ($app) {
            return new HongaAuthClient(
                config('honga-auth.client_id'),
                config('honga-auth.client_secret'),
                config('honga-auth.base_url')
            );
        });

        $this->app->alias(HongaAuthClient::class, 'honga-auth');
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/honga-auth.php' => config_path('honga-auth.php'),
        ], 'honga-auth-config');

        $this->publishes([
            __DIR__.'/../database/migrations/add_honga_user_id_to_users_table.php' => database_path('migrations/'.date('Y_m_d_His').'_add_honga_user_id_to_users_table.php'),
        ], 'honga-auth-migrations');

        $this->loadRoutesFrom(__DIR__.'/../routes/honga-auth.php');

        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallCommand::class,
            ]);
        }

        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('honga.auth', HongaAuthMiddleware::class);
    }
}
