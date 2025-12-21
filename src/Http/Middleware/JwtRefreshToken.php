<?php

namespace Kz370\JwtAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class JwtRefreshToken
{
    public function handle(Request $request, Closure $next)
    {
        if (!$request->has('refresh_token')) {
            return response()->json(['message' => 'Refresh token is required'], 400);
        }

        return $next($request);
    }
}
