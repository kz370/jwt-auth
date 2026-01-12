<?php

namespace Kz370\JwtAuth\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Carbon\Carbon;

class JwtService
{
    protected array $config;
    protected array $algorithms = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function generateAccessToken(Authenticatable $user, array $customClaims = []): string
    {
        $algorithm = $this->config['algorithm'] ?? 'HS256';

        $header = $this->base64UrlEncode(json_encode([
            'alg' => $algorithm,
            'typ' => 'JWT',
        ]));

        $now = Carbon::now();
        $ttl = (int) ($this->config['access_token_ttl'] ?? 15);

        $payload = array_merge([
            'iss' => $this->config['issuer'] ?? config('app.url'),
            'sub' => $user->getAuthIdentifier(),
            'iat' => $now->timestamp,
            'exp' => $now->addMinutes($ttl)->timestamp,
            'nbf' => Carbon::now()->timestamp,
            'jti' => Str::uuid()->toString(),
            'type' => 'access',
        ], $this->config['claims'] ?? [], $customClaims);

        $payloadEncoded = $this->base64UrlEncode(json_encode($payload));

        $signature = $this->sign("{$header}.{$payloadEncoded}", $algorithm);

        return "{$header}.{$payloadEncoded}.{$signature}";
    }

    public function validateAccessToken(string $token): ?array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        [$header, $payload, $signature] = $parts;

        $headerData = json_decode($this->base64UrlDecode($header), true);

        if (!$headerData || !isset($headerData['alg'])) {
            return null;
        }

        $algorithm = $headerData['alg'];

        if (!isset($this->algorithms[$algorithm])) {
            return null;
        }

        $expectedSignature = $this->sign("{$header}.{$payload}", $algorithm);

        if (!hash_equals($expectedSignature, $signature)) {
            return null;
        }

        $payloadData = json_decode($this->base64UrlDecode($payload), true);

        if (!$payloadData) {
            return null;
        }

        if (!$this->validateClaims($payloadData)) {
            return null;
        }

        return $payloadData;
    }

    public function parseToken(string $token): ?array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return null;
        }

        $payload = json_decode($this->base64UrlDecode($parts[1]), true);

        return $payload ?: null;
    }

    protected function validateClaims(array $payload): bool
    {
        $requiredClaims = $this->config['required_claims'] ?? ['iss', 'sub', 'iat', 'exp', 'jti'];

        foreach ($requiredClaims as $claim) {
            if (!isset($payload[$claim])) {
                return false;
            }
        }

        $leeway = (int) ($this->config['leeway'] ?? 60);
        $now = Carbon::now()->timestamp;

        if (isset($payload['exp']) && ($payload['exp'] + $leeway) < $now) {
            return false;
        }

        if (isset($payload['nbf']) && ($payload['nbf'] - $leeway) > $now) {
            return false;
        }

        if (isset($payload['iat']) && ($payload['iat'] - $leeway) > $now) {
            return false;
        }

        if (isset($payload['type']) && $payload['type'] !== 'access') {
            return false;
        }

        return true;
    }

    protected function sign(string $data, string $algorithm): string
    {
        $hashAlgorithm = $this->algorithms[$algorithm] ?? 'sha256';
        $secret = $this->config['secret'] ?? '';

        return $this->base64UrlEncode(
            hash_hmac($hashAlgorithm, $data, $secret, true)
        );
    }

    protected function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function base64UrlDecode(string $data): string
    {
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
