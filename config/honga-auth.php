<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Honga Yetu Authentication Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for connecting to the Honga Yetu central authentication
    | system. These credentials are provided when you register your project.
    |
    */

    'client_id' => env('HONGA_AUTH_CLIENT_ID'),

    'client_secret' => env('HONGA_AUTH_CLIENT_SECRET'),

    'base_url' => env('HONGA_AUTH_URL', 'https://conta.hongayetu.com'),

    /*
    |--------------------------------------------------------------------------
    | Webhook Secret
    |--------------------------------------------------------------------------
    |
    | The secret key used to verify webhook signatures from Honga Yetu.
    | This ensures that webhook requests are authentic.
    |
    */

    'webhook_secret' => env('HONGA_WEBHOOK_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The Eloquent model class that represents users in your application.
    | This model should use the HasHongaUser trait.
    |
    */

    'user_model' => env('HONGA_USER_MODEL', \App\Models\User::class),

    /*
    |--------------------------------------------------------------------------
    | Syncable Fields Mapping
    |--------------------------------------------------------------------------
    |
    | Fields mapping from Honga Yetu to your local user model.
    | Format: 'honga_field' => 'local_field'
    | These fields will be synced on login and when webhooks are received.
    |
    */

    'sync_fields' => [
        'nome' => 'name',
        'email' => 'email',
        'telefone' => 'telefone',
        'foto_link' => 'avatar',
        'aniversario' => 'data_nascimento',
        'genero' => 'genero',
    ],

    /*
    |--------------------------------------------------------------------------
    | Force Honga Authentication
    |--------------------------------------------------------------------------
    |
    | When enabled, users can only authenticate via Honga Yetu.
    | Traditional email/password login will be disabled.
    |
    */

    'force_honga_auth' => env('HONGA_FORCE_AUTH', false),

    /*
    |--------------------------------------------------------------------------
    | Cache Configuration
    |--------------------------------------------------------------------------
    |
    | Token validation results are cached to reduce API calls.
    | Configure the cache duration in minutes.
    |
    */

    'cache' => [
        'enabled' => env('HONGA_CACHE_ENABLED', true),
        'minutes' => env('HONGA_CACHE_MINUTES', 5),
    ],

    /*
    |--------------------------------------------------------------------------
    | Routes Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the routes for OAuth callback and webhooks.
    |
    */

    'routes' => [
        'prefix' => 'honga-auth',
        'middleware' => ['web'],
        'webhook_middleware' => ['api'],
        'login_route' => 'login',
        'register_route' => 'register',
        'home_route' => '/',
        'registration_url' => env('HONGA_REGISTRATION_URL'),
    ],
];
