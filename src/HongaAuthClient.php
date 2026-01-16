<?php

namespace HongaYetu\AuthSDK;

use HongaYetu\AuthSDK\Exceptions\HongaAuthException;
use HongaYetu\AuthSDK\Exceptions\InvalidTokenException;
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

        return $this->baseUrl.'/oauth/authorize?'.http_build_query($params);
    }

    /**
     * Exchange authorization code for access token
     *
     * @throws HongaAuthException
     */
    public function exchangeCodeForToken(string $code, string $redirectUri): array
    {
        $response = Http::post($this->baseUrl.'/oauth/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $redirectUri,
        ]);

        if (! $response->successful()) {
            $error = $response->json();
            throw new HongaAuthException(
                $error['error_description'] ?? 'Erro ao trocar código por token',
                $response->status()
            );
        }

        return $response->json();
    }

    /**
     * Validate access token and get user data
     *
     * @throws InvalidTokenException
     */
    public function validateToken(string $token): array
    {
        $cacheKey = 'honga_token:'.hash('sha256', $token);

        return Cache::remember($cacheKey, now()->addMinutes($this->cacheMinutes), function () use ($token) {
            $response = Http::withToken($token)
                ->post($this->baseUrl.'/api/v1/auth/validate');

            if (! $response->successful()) {
                throw new InvalidTokenException('Token inválido ou expirado');
            }

            $data = $response->json();

            if (! ($data['valid'] ?? false)) {
                throw new InvalidTokenException('Token inválido');
            }

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
     * Register client session for SSO logout tracking
     *
     * @param  string  $accessToken  The access token from OAuth flow
     * @param  string  $hongaSessionId  The session ID from Honga Yetu
     * @param  string  $clientSessionId  The local session ID
     */
    public function registerSession(string $accessToken, string $hongaSessionId, string $clientSessionId): bool
    {
        try {
            $response = Http::withToken($accessToken)
                ->post($this->baseUrl.'/api/v1/auth/sessions', [
                    'honga_session_id' => $hongaSessionId,
                    'client_session_id' => $clientSessionId,
                ]);

            return $response->successful();
        } catch (\Exception $e) {
            // Log but don't fail - session registration is optional
            return false;
        }
    }
}
