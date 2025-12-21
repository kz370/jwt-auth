<?php

namespace Kz370\JwtAuth\Services;

use Kz370\JwtAuth\Models\JwtRefreshToken;
use Carbon\Carbon;
use Illuminate\Support\Str;

class RefreshTokenService
{
    protected array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function create(
        int $userId,
        ?string $deviceName = null,
        ?string $ipAddress = null,
        ?string $userAgent = null,
        ?string $familyId = null
    ): array {
        $rawToken = Str::random(64);
        $tokenHash = hash('sha256', $rawToken);
        $familyId = $familyId ?? Str::uuid()->toString();
        $ttl = $this->config['refresh_token_ttl'] ?? 7;

        $refreshToken = JwtRefreshToken::create([
            'user_id' => $userId,
            'token_hash' => $tokenHash,
            'family_id' => $familyId,
            'device_name' => $deviceName,
            'ip_address' => $ipAddress,
            'user_agent' => $userAgent,
            'expires_at' => Carbon::now()->addDays($ttl),
        ]);

        return [
            'token' => $rawToken,
            'model' => $refreshToken,
        ];
    }

    public function validate(string $rawToken): ?JwtRefreshToken
    {
        $tokenHash = hash('sha256', $rawToken);
        $refreshToken = JwtRefreshToken::where('token_hash', $tokenHash)->first();

        if (!$refreshToken) {
            return null;
        }

        if ($refreshToken->is_revoked) {
            if ($this->config['reuse_detection'] ?? true) {
                $this->revokeFamilyByFamilyId($refreshToken->family_id);
            }
            return null;
        }

        if ($refreshToken->expires_at->isPast()) {
            return null;
        }

        if ($refreshToken->used_at !== null) {
            $gracePeriod = $this->config['blacklist_grace_period'] ?? 30;
            $graceExpiry = $refreshToken->used_at->addSeconds($gracePeriod);

            if (Carbon::now()->isAfter($graceExpiry)) {
                if ($this->config['reuse_detection'] ?? true) {
                    $this->revokeFamilyByFamilyId($refreshToken->family_id);
                }
                return null;
            }
        }

        return $refreshToken;
    }

    public function rotate(
        JwtRefreshToken $oldToken,
        ?string $ipAddress = null,
        ?string $userAgent = null
    ): array {
        $oldToken->update(['used_at' => Carbon::now()]);

        return $this->create(
            $oldToken->user_id,
            $oldToken->device_name,
            $ipAddress ?? $oldToken->ip_address,
            $userAgent ?? $oldToken->user_agent,
            $oldToken->family_id
        );
    }

    public function revoke(string $rawToken): bool
    {
        $tokenHash = hash('sha256', $rawToken);
        $refreshToken = JwtRefreshToken::where('token_hash', $tokenHash)->first();

        if (!$refreshToken) {
            return false;
        }

        $this->revokeFamilyByFamilyId($refreshToken->family_id);
        return true;
    }

    public function revokeFamilyByFamilyId(string $familyId): int
    {
        return JwtRefreshToken::where('family_id', $familyId)
            ->update(['is_revoked' => true]);
    }

    public function revokeAllForUser(int $userId): bool
    {
        JwtRefreshToken::where('user_id', $userId)
            ->update(['is_revoked' => true]);
        return true;
    }

    public function revokeOthers(string $currentRawToken): bool
    {
        $tokenHash = hash('sha256', $currentRawToken);
        $currentToken = JwtRefreshToken::where('token_hash', $tokenHash)->first();

        if (!$currentToken) {
            return false;
        }

        JwtRefreshToken::where('user_id', $currentToken->user_id)
            ->where('family_id', '!=', $currentToken->family_id)
            ->update(['is_revoked' => true]);

        return true;
    }

    public function revokeDevice(int $userId, int $deviceId): bool
    {
        $token = JwtRefreshToken::where('id', $deviceId)
            ->where('user_id', $userId)
            ->first();

        if (!$token) {
            return false;
        }

        $this->revokeFamilyByFamilyId($token->family_id);
        return true;
    }

    public function getActiveDevices(int $userId): array
    {
        return JwtRefreshToken::where('user_id', $userId)
            ->where('is_revoked', false)
            ->where('expires_at', '>', Carbon::now())
            ->whereNull('used_at')
            ->orderBy('created_at', 'desc')
            ->get()
            ->map(function ($token) {
                return [
                    'id' => $token->id,
                    'device_name' => $token->device_name,
                    'ip_address' => $token->ip_address,
                    'created_at' => $token->created_at->toIso8601String(),
                    'expires_at' => $token->expires_at->toIso8601String(),
                ];
            })
            ->toArray();
    }

    public function enforceMaxDevices(int $userId, int $maxDevices): void
    {
        $activeFamilies = JwtRefreshToken::where('user_id', $userId)
            ->where('is_revoked', false)
            ->where('expires_at', '>', Carbon::now())
            ->whereNull('used_at')
            ->orderBy('created_at', 'desc')
            ->get()
            ->unique('family_id')
            ->values();

        if ($activeFamilies->count() >= $maxDevices) {
            $familiesToRevoke = $activeFamilies->slice($maxDevices - 1);

            foreach ($familiesToRevoke as $token) {
                $this->revokeFamilyByFamilyId($token->family_id);
            }
        }
    }

    public function cleanupExpired(): int
    {
        return JwtRefreshToken::where(function ($query) {
            $query->where('expires_at', '<', Carbon::now())
                ->orWhere('is_revoked', true);
        })->delete();
    }
}
