<?php

namespace Kz370\JwtAuth\Http\Middleware;

use Closure;
use Kz370\JwtAuth\Services\JwtService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class JwtAuthenticate
{
    protected JwtService $jwtService;

    public function __construct(JwtService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    public function handle(Request $request, Closure $next)
    {
        $token = $this->extractToken($request);

        if (!$token) {
            return response()->json(['message' => 'Token not provided'], 401);
        }

        $payload = $this->jwtService->validateAccessToken($token);

        if (!$payload) {
            return response()->json(['message' => 'Token is invalid or expired'], 401);
        }

        $guardName = config('jwt-auth.guard_name', 'jwt');

        if (!Auth::guard($guardName)->check()) {
            $userModel = config('jwt-auth.user_model');
            $user = $userModel::find($payload['sub']);

            if (!$user) {
                return response()->json(['message' => 'User not found'], 404);
            }

            Auth::guard($guardName)->setUser($user);
            $request->setUserResolver(fn () => $user);
        } else {
            $user = Auth::guard($guardName)->user();
            $request->setUserResolver(fn () => $user);
        }

        return $next($request);
    }

    protected function extractToken(Request $request): ?string
    {
        $header = $request->header('Authorization', '');
        if (str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }
        return $request->query('token');
    }
}
