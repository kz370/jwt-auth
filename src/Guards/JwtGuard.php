<?php

namespace Kz370\JwtAuth\Guards;

use Kz370\JwtAuth\Services\JwtService;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Authenticatable;

class JwtGuard implements Guard
{
    use GuardHelpers;

    protected JwtService $jwtService;
    protected Request $request;

    public function __construct(
        JwtService $jwtService,
        UserProvider $provider,
        Request $request
    ) {
        $this->jwtService = $jwtService;
        $this->provider = $provider;
        $this->request = $request;
    }

    public function id()
    {
        if ($user = $this->user()) {
            return $user->getAuthIdentifier();
        }

        return null;
    }

    public function user(): ?Authenticatable
    {
        if ($this->user) {
            return $this->user;
        }

        $token = $this->getTokenForRequest();

        if (!$token) {
            return null;
        }

        try {
            $payload = $this->jwtService->validateAccessToken($token);

            if (!$payload) {
                return null;
            }

            $user = $this->provider->retrieveById($payload['sub']);

            if ($user) {
                // If the token contains a refresh token hash (rth), find the session
                if (isset($payload['rth']) && method_exists($user, 'withJwtToken')) {
                    $tokenModel = \Kz370\JwtAuth\Models\JwtRefreshToken::where('token_hash', $payload['rth'])
                        ->where('authenticatable_id', $user->getAuthIdentifier())
                        ->where('authenticatable_type', get_class($user))
                        ->first();
                    
                    if ($tokenModel) {
                        $user->withJwtToken($tokenModel);
                    }
                }

                $this->setUser($user);
                return $user;
            }
        } catch (\Exception $e) {
            // Token validation failed
        }

        return null;
    }

    public function validate(array $credentials = []): bool
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        if ($user && $this->provider->validateCredentials($user, $credentials)) {
            $this->setUser($user);
            return true;
        }

        return false;
    }

    protected function getTokenForRequest(): ?string
    {
        $header = $this->request->header('Authorization', '');

        if (str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }

        return $this->request->query('token');
    }

    public function setRequest(Request $request): self
    {
        $this->request = $request;
        return $this;
    }
}
