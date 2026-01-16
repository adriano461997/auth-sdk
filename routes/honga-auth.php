<?php

use HongaYetu\AuthSDK\Http\Controllers\OAuthCallbackController;
use HongaYetu\AuthSDK\Http\Controllers\WebhookController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Honga Auth SDK Routes
|--------------------------------------------------------------------------
|
| These routes handle OAuth callbacks and webhook notifications
| from the Honga Yetu platform.
|
*/

$prefix = config('honga-auth.routes.prefix', 'honga-auth');

// OAuth routes (web middleware)
Route::prefix($prefix)
    ->middleware(config('honga-auth.routes.middleware', ['web']))
    ->group(function () {
        Route::get('/redirect', [OAuthCallbackController::class, 'redirect'])
            ->name('honga-auth.redirect');

        Route::get('/callback', [OAuthCallbackController::class, 'callback'])
            ->name('honga-auth.callback');

        Route::post('/logout', [OAuthCallbackController::class, 'logout'])
            ->name('honga-auth.logout');

        // Silent logout for front-channel SSO logout (iframe)
        Route::get('/logout-silent', [OAuthCallbackController::class, 'logoutSilent'])
            ->name('honga-auth.logout-silent')
            ->withoutMiddleware(['web', 'auth']);
    });

// Webhook routes (api middleware)
Route::prefix($prefix)
    ->middleware(config('honga-auth.routes.webhook_middleware', ['api']))
    ->group(function () {
        Route::post('/webhook', [WebhookController::class, 'handle'])
            ->name('honga-auth.webhook');
    });
