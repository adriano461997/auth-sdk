<?php

namespace HongaYetu\AuthSDK\Exceptions;

class InvalidTokenException extends HongaAuthException
{
    public function __construct(string $message = 'Token inválido ou expirado', ?\Throwable $previous = null)
    {
        parent::__construct($message, 401, $previous);
    }
}
