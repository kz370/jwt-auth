<?php

namespace Kz370\JwtAuth\Traits;

use Kz370\JwtAuth\Models\JwtRefreshToken;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Carbon\Carbon;

trait HasJwtAuth
{
    /**
     * The current access token (refresh token model) for the user.
     *
     * @var \Kz370\JwtAuth\Models\JwtRefreshToken|null
     */
    protected $currentJwtToken;

    /**
     * Get the refresh tokens for the user.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */
    public function jwtTokens(): HasMany
    {
        return $this->hasMany(JwtRefreshToken::class, 'user_id')
            ->where('is_revoked', false)
            ->where('expires_at', '>', Carbon::now());
    }

    /**
     * Get the current access token for the user.
     *
     * @return \Kz370\JwtAuth\Models\JwtRefreshToken|null
     */
    public function currentJwtToken()
    {
        return $this->currentJwtToken;
    }

    /**
     * Set the current access token for the user.
     *
     * @param  \Kz370\JwtAuth\Models\JwtRefreshToken  $accessToken
     * @return $this
     */
    public function withJwtToken($accessToken)
    {
        $this->currentJwtToken = $accessToken;

        return $this;
    }
}
