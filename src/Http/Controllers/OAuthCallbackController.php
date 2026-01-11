<?php

namespace HongaYetu\AuthSDK\Http\Controllers;

use HongaYetu\AuthSDK\Exceptions\HongaAuthException;
use HongaYetu\AuthSDK\HongaAuthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;

class OAuthCallbackController extends Controller
{
    protected HongaAuthClient $client;

    public function __construct(HongaAuthClient $client)
    {
        $this->client = $client;
    }

    /**
     * Redirect to Honga Yetu for authentication
     */
    public function redirect(Request $request): RedirectResponse
    {
        $state = bin2hex(random_bytes(16));
        Session::put('honga_auth_state', $state);

        $redirectUri = route('honga-auth.callback');

        $url = $this->client->getAuthorizationUrl($redirectUri, $state);

        return redirect()->away($url);
    }

    /**
     * Handle OAuth callback from Honga Yetu
     */
    public function callback(Request $request): RedirectResponse
    {
        if ($request->has('error')) {
            Log::error('HongaAuth: OAuth error', [
                'error' => $request->get('error'),
                'description' => $request->get('error_description'),
            ]);

            return redirect()
                ->route(config('honga-auth.routes.login_route', 'login'))
                ->with('error', $request->get('error_description', 'Erro na autenticação'));
        }

        $state = $request->get('state');
        $expectedState = Session::pull('honga_auth_state');

        if (! $state || $state !== $expectedState) {
            Log::warning('HongaAuth: Invalid state parameter');

            return redirect()
                ->route(config('honga-auth.routes.login_route', 'login'))
                ->with('error', 'Estado de sessão inválido');
        }

        $code = $request->get('code');

        if (! $code) {
            return redirect()
                ->route(config('honga-auth.routes.login_route', 'login'))
                ->with('error', 'Código de autorização não fornecido');
        }

        try {
            $redirectUri = route('honga-auth.callback');
            $tokenData = $this->client->exchangeCodeForToken($code, $redirectUri);

            $userData = $tokenData['user'] ?? [];

            if (empty($userData)) {
                throw new HongaAuthException('Dados do utilizador não disponíveis');
            }

            $userModel = config('honga-auth.user_model');
            $user = $userModel::findByHongaUser($userData);

            // User not found - must register first
            if (! $user) {
                Log::info('HongaAuth: User not found, redirect to register', [
                    'honga_user_id' => $userData['id'] ?? null,
                    'email' => $userData['email'] ?? null,
                ]);

                // Store Honga data temporarily for registration
                Session::put('honga_pending_user', $userData);
                Session::put('honga_access_token', $tokenData['access_token']);

                return redirect()
                    ->route(config('honga-auth.routes.register_route', 'register'))
                    ->with('info', 'Conta não encontrada. Por favor, crie uma conta primeiro.');
            }

            Session::put('honga_access_token', $tokenData['access_token']);
            Session::put('honga_token_expires_at', now()->addSeconds($tokenData['expires_in'] ?? 3600));

            Auth::login($user);

            Log::info('HongaAuth: User authenticated', [
                'local_user_id' => $user->id,
                'honga_user_id' => $userData['id'] ?? null,
            ]);

            return redirect()->intended(
                config('honga-auth.routes.home_route', '/')
            );

        } catch (HongaAuthException $e) {
            Log::error('HongaAuth: Token exchange failed', [
                'error' => $e->getMessage(),
            ]);

            return redirect()
                ->route(config('honga-auth.routes.login_route', 'login'))
                ->with('error', $e->getMessage());
        }
    }

    /**
     * Logout from Honga Yetu
     */
    public function logout(Request $request): RedirectResponse
    {
        $token = Session::pull('honga_access_token');

        if ($token) {
            try {
                $this->client->revokeToken($token);
            } catch (\Exception $e) {
                Log::warning('HongaAuth: Failed to revoke token', [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        Session::forget(['honga_access_token', 'honga_token_expires_at']);
        Auth::logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route(config('honga-auth.routes.login_route', 'login'));
    }
}
