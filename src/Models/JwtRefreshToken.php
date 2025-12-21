<?php

namespace Kz370\JwtAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

class JwtRefreshToken extends Model
{
    protected $fillable = [
        'authenticatable_id',
        'authenticatable_type',
        'token_hash',
        'family_id',
        'device_name',
        'ip_address',
        'user_agent',
        'expires_at',
        'used_at',
        'is_revoked',
    ];

    protected $casts = [
        'expires_at' => 'datetime',
        'used_at' => 'datetime',
        'is_revoked' => 'boolean',
    ];

    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);
        $this->setTable(config('jwt-auth.table_name', 'jwt_refresh_tokens'));
    }

    /**
     * Get the parent authenticatable model (User, Admin, etc.).
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Alias for authenticatable for compatibility.
     */
    public function user()
    {
        return $this->authenticatable();
    }

    /**
     * Compatibility with user's snippet ($token->name)
     */
    public function getNameAttribute()
    {
        return $this->device_name;
    }

    /**
     * Compatibility with user's snippet ($token->last_used_at)
     */
    public function getLastUsedAtAttribute()
    {
        return $this->used_at;
    }
}
