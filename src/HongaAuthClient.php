<?php

namespace HongaYetu\AuthSDK;

use HongaYetu\AuthSDK\Exceptions\HongaAuthException;
use HongaYetu\AuthSDK\Exceptions\InvalidTokenException;
use HongaYetu\AuthSDK\Support\HongaLogger;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class HongaAuthClient
{
    protected string $clientId;

    protected string $clientSecret;

    protected string $baseUrl;

    protected int $cacheMinutes = 5;

    public function __construct(string $clientId, string $clientSecret, string $baseUrl)
    {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Get the authorization URL for redirect
     */
    public function getAuthorizationUrl(string $redirectUri, ?string $state = null): string
    {
        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'response_type' => 'code',
        ];

        if ($state) {
            $params['state'] = $state;
        }

        $url = $this->baseUrl.'/oauth/authorize?'.http_build_query($params);

        HongaLogger::debug('Generated authorization URL', [
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'url' => $url,
        ]);

        return $url;
    }

    /**
     * Exchange authorization code for access token
     *
     * @throws HongaAuthException
     */
    public function exchangeCodeForToken(string $code, string $redirectUri): array
    {
        HongaLogger::debug('Exchanging code for token', [
            'code' => substr($code, 0, 10).'...',
            'redirect_uri' => $redirectUri,
        ]);

        $response = Http::post($this->baseUrl.'/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $redirectUri,
        ]);

        if (! $response->successful()) {
            $error = $response->json();
            HongaLogger::error('Token exchange failed', [
                'status' => $response->status(),
                'error' => $error,
            ]);
            throw new HongaAuthException(
                $error['error_description'] ?? 'Erro ao trocar código por token',
                $response->status()
            );
        }

        $data = $response->json();

        HongaLogger::info('Token exchange successful', [
            'has_access_token' => isset($data['access_token']),
            'has_user' => isset($data['user']),
            'has_honga_session_id' => isset($data['honga_session_id']),
            'expires_in' => $data['expires_in'] ?? null,
        ]);

        return $data;
    }

    /**
     * Validate access token and get user data
     *
     * @throws InvalidTokenException
     */
    public function validateToken(string $token): array
    {
        $cacheKey = 'honga_token:'.hash('sha256', $token);

        HongaLogger::debug('Validating token', [
            'cache_key' => $cacheKey,
        ]);

        return Cache::remember($cacheKey, now()->addMinutes($this->cacheMinutes), function () use ($token) {
            HongaLogger::debug('Token not in cache, calling API');

            $response = Http::withToken($token)
                ->post($this->baseUrl.'/api/v1/auth/validate');

            if (! $response->successful()) {
                HongaLogger::warning('Token validation failed', [
                    'status' => $response->status(),
                ]);
                throw new InvalidTokenException('Token inválido ou expirado');
            }

            $data = $response->json();

            if (! ($data['valid'] ?? false)) {
                HongaLogger::warning('Token marked as invalid');
                throw new InvalidTokenException('Token inválido');
            }

            HongaLogger::info('Token validated successfully', [
                'user_id' => $data['user']['id'] ?? null,
            ]);

            return $data;
        });
    }

    /**
     * Refresh access token
     *
     * @throws HongaAuthException
     */
    public function refreshToken(string $token): array
    {
        $response = Http::withToken($token)
            ->post($this->baseUrl.'/api/v1/auth/refresh');

        if (! $response->successful()) {
            throw new HongaAuthException('Erro ao renovar token', $response->status());
        }

        $this->invalidateTokenCache($token);

        return $response->json();
    }

    /**
     * Revoke access token
     */
    public function revokeToken(string $token): bool
    {
        $response = Http::withToken($token)
            ->post($this->baseUrl.'/api/v1/auth/revoke');

        $this->invalidateTokenCache($token);

        return $response->successful();
    }

    /**
     * Get user info from token
     *
     * @throws InvalidTokenException
     */
    public function getUser(string $token): array
    {
        $data = $this->validateToken($token);

        return $data['user'] ?? [];
    }

    /**
     * Validate webhook signature
     */
    public function validateWebhookSignature(string $payload, string $signature, string $secret): bool
    {
        $expectedSignature = hash_hmac('sha256', $payload, $secret);

        return hash_equals($expectedSignature, $signature);
    }

    /**
     * Invalidate token cache
     */
    protected function invalidateTokenCache(string $token): void
    {
        $cacheKey = 'honga_token:'.hash('sha256', $token);
        Cache::forget($cacheKey);
    }

    /**
     * Set cache duration in minutes
     */
    public function setCacheMinutes(int $minutes): self
    {
        $this->cacheMinutes = $minutes;

        return $this;
    }

    /**
     * Get the base URL
     */
    public function getBaseUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * Get client ID
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * Get the SSO logout URL with continue parameter
     *
     * @param  string|null  $continueUrl  URL to redirect after logout (defaults to login route)
     * @return string The SSO logout URL
     */
    public function getSsoLogoutUrl(?string $continueUrl = null): string
    {
        // Usar /sair (mesmo endpoint que logout interno)
        $logoutUrl = config('honga-auth.logout_url', $this->baseUrl . '/sair');

        if (!$continueUrl) {
            // Usar logout_redirect_url se definido, senão usa a raiz da aplicação
            $logoutRedirectUrl = config('honga-auth.routes.logout_redirect_url');
            $continueUrl = $logoutRedirectUrl ?: url('/');
        }

        // Obter honga_session_id da sessão (guardado durante OAuth callback)
        $hongaSessionId = session('honga_session_id');

        $params = ['continue' => $continueUrl];
        if ($hongaSessionId) {
            $params['session'] = $hongaSessionId;
        }

        $url = $logoutUrl . '?' . http_build_query($params);

        HongaLogger::debug('Generated SSO logout URL', [
            'logout_url' => $logoutUrl,
            'continue_url' => $continueUrl,
            'has_session' => !empty($hongaSessionId),
        ]);

        return $url;
    }

    /**
     * Register client session for SSO logout tracking
     *
     * @param  string  $accessToken  The access token from OAuth flow
     * @param  string  $hongaSessionId  The session ID from Honga Yetu
     * @param  string  $clientSessionId  The local session ID
     */
    public function registerSession(string $accessToken, string $hongaSessionId, string $clientSessionId): bool
    {
        HongaLogger::debug('Registering session for SSO logout', [
            'honga_session_id' => $hongaSessionId,
            'client_session_id' => $clientSessionId,
        ]);

        try {
            $response = Http::withToken($accessToken)
                ->post($this->baseUrl.'/api/v1/auth/sessions', [
                    'honga_session_id' => $hongaSessionId,
                    'client_session_id' => $clientSessionId,
                ]);

            if ($response->successful()) {
                HongaLogger::info('Session registered successfully', [
                    'honga_session_id' => $hongaSessionId,
                    'client_session_id' => $clientSessionId,
                ]);

                return true;
            }

            HongaLogger::warning('Session registration failed', [
                'status' => $response->status(),
                'response' => $response->json(),
            ]);

            return false;
        } catch (\Exception $e) {
            HongaLogger::error('Session registration exception', [
                'error' => $e->getMessage(),
            ]);

            return false;
        }
    }
}
