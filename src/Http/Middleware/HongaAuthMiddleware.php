<?php

namespace HongaYetu\AuthSDK\Http\Middleware;

use Closure;
use HongaYetu\AuthSDK\Exceptions\InvalidTokenException;
use HongaYetu\AuthSDK\HongaAuthClient;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class HongaAuthMiddleware
{
    protected HongaAuthClient $client;

    public function __construct(HongaAuthClient $client)
    {
        $this->client = $client;
    }

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $token = $this->extractBearerToken($request);

        if (! $token) {
            return response()->json([
                'error' => 'unauthorized',
                'message' => 'Token de autenticação não fornecido',
            ], 401);
        }

        try {
            $userData = $this->client->validateToken($token);

            $request->merge([
                'honga_user' => $userData['user'] ?? [],
                'honga_token' => $token,
            ]);

            $request->attributes->set('honga_user', $userData['user'] ?? []);
            $request->attributes->set('honga_token', $token);

        } catch (InvalidTokenException $e) {
            return response()->json([
                'error' => 'invalid_token',
                'message' => $e->getMessage(),
            ], 401);
        }

        return $next($request);
    }

    /**
     * Extract bearer token from request
     */
    protected function extractBearerToken(Request $request): ?string
    {
        $header = $request->header('Authorization');

        if (! $header) {
            return $request->query('access_token');
        }

        if (preg_match('/Bearer\s+(.+)/i', $header, $matches)) {
            return $matches[1];
        }

        return null;
    }
}
