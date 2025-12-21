<?php

return [
    /*
    |--------------------------------------------------------------------------
    | JWT Secret Key
    |--------------------------------------------------------------------------
    |
    | This key is used to sign the JWT tokens. Keep this secret and never
    | expose it publicly. Use a strong, random string of at least 32 characters.
    | Generate one using: php artisan jwt:secret
    |
    */
    'secret' => env('JWT_SECRET', ''),

    /*
    |--------------------------------------------------------------------------
    | JWT Algorithm
    |--------------------------------------------------------------------------
    |
    | The algorithm used to sign the JWT tokens.
    | Supported: HS256, HS384, HS512
    |
    */
    'algorithm' => env('JWT_ALGORITHM', 'HS256'),

    /*
    |--------------------------------------------------------------------------
    | Access Token TTL (Time To Live)
    |--------------------------------------------------------------------------
    |
    | The time-to-live (TTL) for access tokens in minutes.
    | Recommended: 15 minutes for high security, up to 60 for convenience.
    |
    */
    'access_token_ttl' => env('JWT_ACCESS_TOKEN_TTL', 15),

    /*
    |--------------------------------------------------------------------------
    | Refresh Token TTL
    |--------------------------------------------------------------------------
    |
    | The time-to-live (TTL) for refresh tokens in days.
    | Recommended: 7 days for high security, up to 30 for convenience.
    |
    */
    'refresh_token_ttl' => env('JWT_REFRESH_TOKEN_TTL', 7),

    /*
    |--------------------------------------------------------------------------
    | Token Blacklist Enabled
    |--------------------------------------------------------------------------
    |
    | When enabled, tokens will be blacklisted when logout is called.
    | This provides an extra layer of security by preventing token reuse.
    |
    */
    'blacklist_enabled' => env('JWT_BLACKLIST_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Blacklist Grace Period
    |--------------------------------------------------------------------------
    |
    | When multiple requests are made with the same token, this setting
    | allows for a grace period (in seconds) to prevent token blacklist
    | race conditions.
    |
    */
    'blacklist_grace_period' => env('JWT_BLACKLIST_GRACE_PERIOD', 30),

    /*
    |--------------------------------------------------------------------------
    | Refresh Token Rotation
    |--------------------------------------------------------------------------
    |
    | When enabled, a new refresh token will be issued each time the
    | access token is refreshed. The old refresh token will be invalidated.
    | This is recommended for better security.
    |
    */
    'rotate_refresh_token' => env('JWT_ROTATE_REFRESH_TOKEN', true),

    /*
    |--------------------------------------------------------------------------
    | Refresh Token Reuse Detection
    |--------------------------------------------------------------------------
    |
    | When enabled, if a refresh token that has already been used is
    | presented, all tokens in the same family will be revoked.
    | This protects against token theft.
    |
    */
    'reuse_detection' => env('JWT_REUSE_DETECTION', true),

    /*
    |--------------------------------------------------------------------------
    | User Model
    |--------------------------------------------------------------------------
    |
    | The user model class to use for authentication.
    |
    */
    'user_model' => env('JWT_USER_MODEL', 'App\\Models\\User'),

    /*
    |--------------------------------------------------------------------------
    | User Identifier
    |--------------------------------------------------------------------------
    |
    | The column name used as the unique identifier for users.
    |
    */
    'user_identifier' => 'id',

    /*
    |--------------------------------------------------------------------------
    | Database Table
    |--------------------------------------------------------------------------
    |
    | The database table name for storing refresh tokens.
    |
    */
    'table_name' => 'jwt_refresh_tokens',

    /*
    |--------------------------------------------------------------------------
    | Token Claims
    |--------------------------------------------------------------------------
    |
    | Additional claims to include in the JWT payload.
    | You can add custom claims like 'role', 'permissions', etc.
    |
    */
    'claims' => [
        // 'custom_claim' => 'value',
    ],

    /*
    |--------------------------------------------------------------------------
    | Leeway
    |--------------------------------------------------------------------------
    |
    | This property gives the JWT a "leeway" in seconds to account for
    | clock skew between servers. Recommended: 60 seconds.
    |
    */
    'leeway' => env('JWT_LEEWAY', 60),

    /*
    |--------------------------------------------------------------------------
    | Required Claims
    |--------------------------------------------------------------------------
    |
    | Claims that must be present in every JWT.
    |
    */
    'required_claims' => [
        'iss',
        'sub',
        'iat',
        'exp',
        'jti',
    ],

    /*
    |--------------------------------------------------------------------------
    | Issuer
    |--------------------------------------------------------------------------
    |
    | The issuer claim for the JWT. Typically your application URL.
    |
    */
    'issuer' => env('JWT_ISSUER', env('APP_URL', 'http://localhost')),

    /*
    |--------------------------------------------------------------------------
    | Cleanup Expired Tokens
    |--------------------------------------------------------------------------
    |
    | Automatically cleanup expired refresh tokens on each refresh request.
    | Set to false if you handle cleanup via a scheduled command.
    |
    */
    'cleanup_expired' => env('JWT_CLEANUP_EXPIRED', true),

    /*
    |--------------------------------------------------------------------------
    | Maximum Devices Per User
    |--------------------------------------------------------------------------
    |
    | Maximum number of active refresh token families (devices) allowed per user.
    | Set to 0 for unlimited. Oldest sessions will be revoked when limit is reached.
    |
    */
    'max_devices' => env('JWT_MAX_DEVICES', 5),

    /*
    |--------------------------------------------------------------------------
    | Guard Name
    |--------------------------------------------------------------------------
    |
    | The name of the authentication guard that will be automatically registered.
    | Default: 'jwt'
    |
    */
    'guard_name' => env('JWT_GUARD_NAME', 'jwt'),

    /*
    |--------------------------------------------------------------------------
    | Override Default Guard
    |--------------------------------------------------------------------------
    |
    | If set to true, the package will automatically set the 'guard_name'
    | as the default authentication guard for the entire application.
    | Default: false
    |
    */
    'override_default_guard' => env('JWT_OVERRIDE_DEFAULT_GUARD', false),
];
