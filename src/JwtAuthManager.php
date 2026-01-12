<?php

namespace Kz370\JwtAuth;

use Kz370\JwtAuth\Services\JwtService;
use Kz370\JwtAuth\Services\RefreshTokenService;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;

class JwtAuthManager
{
    protected JwtService $jwtService;
    protected RefreshTokenService $refreshTokenService;
    protected array $config;
    protected ?Request $request;

    public function __construct(
        JwtService $jwtService,
        RefreshTokenService $refreshTokenService,
        array $config,
        ?Request $request = null
    ) {
        $this->jwtService = $jwtService;
        $this->refreshTokenService = $refreshTokenService;
        $this->config = $config;
        $this->request = $request;
    }

    public function attempt(array $credentials, $deviceInfo = []): ?array
    {
        $userModel = $this->config['user_model'];
        $user = $userModel::where('email', $credentials['email'])->first();

        if (!$user || !password_verify($credentials['password'], $user->password)) {
            return null;
        }

        return $this->login($user, $deviceInfo);
    }

    public function login(Authenticatable $user, $deviceInfo = []): array
    {
        $this->enforceMaxDevices($user);

        if (is_string($deviceInfo)) {
            $deviceInfo = ['device_name' => $deviceInfo];
        }

        $ipAddress = $deviceInfo['ip_address'] ?? ($this->request ? $this->request->ip() : null);
        $userAgent = $deviceInfo['user_agent'] ?? ($this->request ? $this->request->userAgent() : null);

        $refreshTokenData = $this->refreshTokenService->create(
            $user,
            $deviceInfo['device_name'] ?? null,
            $ipAddress,
            $userAgent
        );

        $accessToken = $this->jwtService->generateAccessToken($user, [
            'rth' => hash('sha256', $refreshTokenData['token'])
        ]);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshTokenData['token'],
            'token_type' => 'Bearer',
            'expires_in' => (int) $this->config['access_token_ttl'] * 60,
            'refresh_expires_in' => (int) $this->config['refresh_token_ttl'] * 24 * 60 * 60,
        ];
    }

    public function refresh(string $refreshToken, ?string $ipAddress = null, ?string $userAgent = null): ?array
    {
        $tokenRecord = $this->refreshTokenService->validate($refreshToken);

        if (!$tokenRecord) {
            return null;
        }

        if ($this->config['cleanup_expired']) {
            $this->refreshTokenService->cleanupExpired();
        }

        $user = $tokenRecord->authenticatable;

        if (!$user) {
            return null;
        }

        $ipAddress = $ipAddress ?? ($this->request ? $this->request->ip() : null);
        $userAgent = $userAgent ?? ($this->request ? $this->request->userAgent() : null);

        $newRefreshTokenData = null;

        if ($this->config['rotate_refresh_token']) {
            $newRefreshTokenData = $this->refreshTokenService->rotate(
                $tokenRecord,
                $ipAddress,
                $userAgent
            );
        }

        $accessToken = $this->jwtService->generateAccessToken($user, [
            'rth' => hash('sha256', $newRefreshTokenData ? $newRefreshTokenData['token'] : $refreshToken)
        ]);

        return [
            'access_token' => $accessToken,
            'refresh_token' => $newRefreshTokenData ? $newRefreshTokenData['token'] : $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => (int) $this->config['access_token_ttl'] * 60,
            'refresh_expires_in' => (int) $this->config['refresh_token_ttl'] * 24 * 60 * 60,
        ];
    }

    public function logout(string $refreshToken): bool
    {
        return $this->refreshTokenService->revoke($refreshToken);
    }

    public function logoutAll(Authenticatable $user): bool
    {
        return $this->refreshTokenService->revokeAllForUser($user);
    }

    public function logoutOthers(string $currentRefreshToken): bool
    {
        return $this->refreshTokenService->revokeOthers($currentRefreshToken);
    }

    public function getDevices(Authenticatable $user): array
    {
        return $this->refreshTokenService->getActiveDevices($user);
    }

    public function revokeDevice(Authenticatable $user, int $deviceId): bool
    {
        return $this->refreshTokenService->revokeDevice($user, $deviceId);
    }

    public function validateAccessToken(string $token): ?array
    {
        return $this->jwtService->validateAccessToken($token);
    }

    public function parseToken(string $token): ?array
    {
        return $this->jwtService->parseToken($token);
    }

    public function getUserFromToken(string $token): ?Authenticatable
    {
        $payload = $this->validateAccessToken($token);

        if (!$payload) {
            return null;
        }

        $userModel = $this->config['user_model'];
        return $userModel::find($payload['sub']);
    }

    public function setRequest(Request $request): self
    {
        $this->request = $request;
        return $this;
    }

    protected function enforceMaxDevices(Authenticatable $user): void
    {
        $maxDevices = (int) ($this->config['max_devices'] ?? 5);

        if ($maxDevices <= 0) {
            return;
        }

        $this->refreshTokenService->enforceMaxDevices($user, $maxDevices);
    }
}
