<?php

namespace Kz370\JwtAuth;

use Kz370\JwtAuth\Services\JwtService;
use Kz370\JwtAuth\Services\RefreshTokenService;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtAuthManager
{
    protected JwtService $jwtService;
    protected RefreshTokenService $refreshTokenService;
    protected array $config;

    public function __construct(
        JwtService $jwtService,
        RefreshTokenService $refreshTokenService,
        array $config
    ) {
        $this->jwtService = $jwtService;
        $this->refreshTokenService = $refreshTokenService;
        $this->config = $config;
    }

    public function attempt(array $credentials, array $deviceInfo = []): ?array
    {
        $userModel = $this->config['user_model'];
        $user = $userModel::where('email', $credentials['email'])->first();

        if (!$user || !password_verify($credentials['password'], $user->password)) {
            return null;
        }

        return $this->login($user, $deviceInfo);
    }

    public function login(Authenticatable $user, array $deviceInfo = []): array
    {
        $this->enforceMaxDevices($user->getAuthIdentifier());

        $accessToken = $this->jwtService->generateAccessToken($user);
        $refreshTokenData = $this->refreshTokenService->create(
            $user->getAuthIdentifier(),
            $deviceInfo['device_name'] ?? null,
            $deviceInfo['ip_address'] ?? null,
            $deviceInfo['user_agent'] ?? null
        );

        return [
            'access_token' => $accessToken,
            'refresh_token' => $refreshTokenData['token'],
            'token_type' => 'Bearer',
            'expires_in' => $this->config['access_token_ttl'] * 60,
            'refresh_expires_in' => $this->config['refresh_token_ttl'] * 24 * 60 * 60,
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

        $userModel = $this->config['user_model'];
        $user = $userModel::find($tokenRecord->user_id);

        if (!$user) {
            return null;
        }

        $accessToken = $this->jwtService->generateAccessToken($user);
        $newRefreshTokenData = null;

        if ($this->config['rotate_refresh_token']) {
            $newRefreshTokenData = $this->refreshTokenService->rotate(
                $tokenRecord,
                $ipAddress,
                $userAgent
            );
        }

        return [
            'access_token' => $accessToken,
            'refresh_token' => $newRefreshTokenData ? $newRefreshTokenData['token'] : $refreshToken,
            'token_type' => 'Bearer',
            'expires_in' => $this->config['access_token_ttl'] * 60,
            'refresh_expires_in' => $this->config['refresh_token_ttl'] * 24 * 60 * 60,
        ];
    }

    public function logout(string $refreshToken): bool
    {
        return $this->refreshTokenService->revoke($refreshToken);
    }

    public function logoutAll(int $userId): bool
    {
        return $this->refreshTokenService->revokeAllForUser($userId);
    }

    public function logoutOthers(string $currentRefreshToken): bool
    {
        return $this->refreshTokenService->revokeOthers($currentRefreshToken);
    }

    public function getDevices(int $userId): array
    {
        return $this->refreshTokenService->getActiveDevices($userId);
    }

    public function revokeDevice(int $userId, int $deviceId): bool
    {
        return $this->refreshTokenService->revokeDevice($userId, $deviceId);
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

    protected function enforceMaxDevices(int $userId): void
    {
        $maxDevices = $this->config['max_devices'];

        if ($maxDevices <= 0) {
            return;
        }

        $this->refreshTokenService->enforceMaxDevices($userId, $maxDevices);
    }
}
