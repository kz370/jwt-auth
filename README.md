# Laravel JWT Auth

[![Latest Version on Packagist](https://img.shields.io/packagist/v/kz370/jwt-auth.svg?style=flat-square)](https://packagist.org/packages/kz370/jwt-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/kz370/jwt-auth.svg?style=flat-square)](https://packagist.org/packages/kz370/jwt-auth)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![PHP Version](https://img.shields.io/badge/php-%5E8.0-blue.svg?style=flat-square)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/laravel-%5E9.0%20%7C%20%5E10.0%20%7C%20%5E11.0-red.svg?style=flat-square)](https://laravel.com)

A sophisticated, secure, and developer-friendly JWT authentication package for Laravel. Designed with a dual-token architecture (Access + Refresh tokens) and advanced security features like automatic rotation and replay attack detection.

---

## 🚀 Key Features

- **Dual-Token Architecture**: Implements short-lived Access Tokens for security and long-lived Refresh Tokens for a seamless user experience.
- **Secure Token Management**: All refresh tokens are hashed (SHA-256) before storage, ensuring data safety even in the event of a database compromise.
- **Automatic Token Rotation**: Implements a "sliding session" approach where a new refresh token is issued on every use, immediately invalidating the previous one.
- **Advanced Replay Detection**: Real-time monitoring of token families. If a previously used refresh token is re-submitted, the system detects a breach and revokes the entire token family.
- **Granular Device Control**: Native support for tracking, listing, and revoking specific device sessions from anywhere in your application.
- **Zero-Config Integration**: Drop-in replacement for standard Laravel guards (Sanctum/Passport).

---

## 📦 Installation

Install the package via Composer:

```bash
composer require kz370/jwt-auth
```

### 1. Run Migrations
The package requires specific tables to manage token families and device sessions.

```bash
php artisan migrate
```

### 2. Publish Configuration (Optional)
Customize the TTL (Time-To-Live), signing algorithm, and other settings:

```bash
php artisan vendor:publish --tag=jwt-auth-config
```

### 3. Generate JWT Secret
Generate a secure signing key for your tokens. This will be added to your `.env` file:

```bash
php artisan jwt:secret
```

---

## 👨‍💻 User Model Setup

To enable session management and token relationships on your User model, add the `HasJwtAuth` trait:

```php
use Kz370\JwtAuth\Traits\HasJwtAuth;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasJwtAuth;
    
    // ...
}
```

This trait provides several helper methods:
- `$user->jwtTokens`: Get all active sessions.
- `$user->currentJwtToken()`: Get the session model for the current request.

---

## 🎭 Multi-Model & Multi-Guard Support

The package is not limited to the `User` model. You can use it with any Eloquent model (Admins, Customers, etc.) and even manage multiple guards simultaneously.

### 1. Custom Model
If you only use one model but it's not `App\Models\User`, update your `config/jwt-auth.php`:
```php
'user_model' => App\Models\Admin::class,
```

### 2. Multiple Guards (e.g., User and Admin)
If you need separate authentication for different tables, define them in `config/auth.php`:

```php
// config/auth.php
'guards' => [
    'jwt' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
    'admin-jwt' => [
        'driver' => 'jwt',
        'provider' => 'admins',
    ],
],

'providers' => [
    'users' => [
        'driver' => 'eloquent',
        'model' => App\Models\User::class,
    ],
    'admins' => [
        'driver' => 'eloquent',
        'model' => App\Models\Admin::class,
    ],
],
```

Then protect your routes accordingly:
```php
Route::middleware('auth:admin-jwt')->get('/admin/profile', ...);
```

> **Note:** Ensure every model used for authentication includes the `HasJwtAuth` trait.

---

## ⚙️ Configuration

### Automatic Guard Registration
The package automatically registers a `jwt` authentication guard. To use it as your default for API routes, update your `config/jwt-auth.php`:

```php
// config/jwt-auth.php
'override_default_guard' => true,
```

---

## 🛡 Middleware Usage

The package provides two middlewares out of the box to help you secure your routes.

### 1. `jwt.auth`
Protects routes that require a valid Access Token. It automatically validates the JWT and sets the authenticated user for the request.

```php
// routes/api.php
Route::middleware('jwt.auth')->get('/user', function (Request $request) {
    return $request->user();
});
```

### 2. `jwt.refresh`
Ensures that the request contains a `refresh_token`. Useful for specific refresh or logout endpoints.

```php
Route::middleware('jwt.refresh')->post('/refresh', [AuthController::class, 'refresh']);
```

---

## ⚡ Integration with Existing Auth

If you are migrating from **Laravel Sanctum** or **Passport**, you simply need to replace your token generation logic in your authentication controllers.

Find where you currently generate tokens (e.g., `$user->createToken(...)`) and replace it with the `JwtAuth` facade:

```php
use Kz370\JwtAuth\Facades\JwtAuth;

public function login(Request $request) 
{
    // ... your validation logic ...
    $user = User::where('email', $request->email)->first();

    // Replace $user->createToken('...')->plainTextToken with:
    $tokens = JwtAuth::login($user, [
        'device_name' => $request->userAgent(),
    ]);

    // $tokens content: ['access_token', 'refresh_token', 'expires_in', ...]
    return response()->json($tokens);
}
```

This ensures that users transitioning to this package correctly adopt the new dual-token system without leaving behind outdated logic.

---

## 🛠 Usage

### Authentication (The Facade)
The `JwtAuth` facade is the primary entry point for all operations.

#### User Login (Credentials)
```php
use Kz370\JwtAuth\Facades\JwtAuth;

public function login(Request $request)
{
    $credentials = $request->only('email', 'password');
    
    // Optional: Pass device metadata for session tracking
    $deviceInfo = [
        'device_name' => $request->header('User-Agent'),
        'ip_address'  => $request->ip(),
    ];

    $tokens = JwtAuth::attempt($credentials, $deviceInfo);

    if (!$tokens) {
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    return response()->json($tokens);
}
```

#### Token Refresh
Exchange a refresh token for a brand new pair of tokens (rotates the family).
```php
public function refresh(Request $request)
{
    $tokens = JwtAuth::refresh($request->refresh_token);

    if (!$tokens) {
        return response()->json(['error' => 'Invalid or expired token'], 401);
    }

    return response()->json($tokens);
}
```

#### Logout
Invalidates the current refresh token and session. Returns `true` on success, or `false` if the token is invalid/expired.
```php
public function logout(Request $request)
{
    $revoked = JwtAuth::logout($request->refresh_token);
    
    if (!$revoked) {
        return response()->json(['message' => 'Invalid or already revoked token'], 401);
    }

    return response()->json(['message' => 'Logged out successfully']);
}
```

---

## 📱 Device & Session Management

Take full control of user sessions across multiple devices:

```php
// List all active sessions for a user
$sessions = JwtAuth::getDevices($userId);

// Revoke a specific session
JwtAuth::revokeDevice($userId, $sessionId);

// Global Logout: Revoke all sessions for a user
JwtAuth::logoutAll($userId);

// Revoke all OTHER sessions (stay logged in on current device)
JwtAuth::logoutOthers($currentRefreshToken);
```

---

## 🔒 Security Design

### Family IDs & Token Rotation
Every login starts a "Token Family". When you refresh, the old refresh token is revoked, and a new one is issued within the same family. 

### Replay Attack Protection
If a used refresh token is ever presented again (indicating it was stolen and replayed), the package detects this immediately and **revokes every token in that family**, forcing the legitimate user to re-authenticate and securing the account.

---

## 🖥 Console Commands

| Command | Description |
| :--- | :--- |
| `php artisan jwt:secret` | Generates a 64-character secret key for JWT signing. |
| `php artisan jwt:cleanup` | Removes expired and revoked tokens from the database. |

*Recommendation: Schedule the cleanup command to run daily:*
```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;
Schedule::command('jwt:cleanup')->daily();
```

---

## 📄 License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
