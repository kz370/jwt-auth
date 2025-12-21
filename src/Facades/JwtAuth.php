<?php

namespace Kz370\JwtAuth\Facades;

use Illuminate\Support\Facades\Facade;

class JwtAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'jwt-auth';
    }
}
