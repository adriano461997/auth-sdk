<?php

namespace HongaYetu\AuthSDK\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string getAuthorizationUrl(string $redirectUri, ?string $state = null)
 * @method static array exchangeCodeForToken(string $code, string $redirectUri)
 * @method static array validateToken(string $token)
 * @method static array refreshToken(string $token)
 * @method static bool revokeToken(string $token)
 * @method static array getUser(string $token)
 * @method static bool validateWebhookSignature(string $payload, string $signature, string $secret)
 * @method static string getBaseUrl()
 * @method static string getClientId()
 * @method static string getSsoLogoutUrl(?string $continueUrl = null)
 * @method static bool registerSession(string $accessToken, string $hongaSessionId, string $clientSessionId)
 *
 * @see \HongaYetu\AuthSDK\HongaAuthClient
 */
class HongaAuth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'honga-auth';
    }
}
