<?php

namespace HongaYetu\AuthSDK\Http\Controllers;

use HongaYetu\AuthSDK\Exceptions\HongaAuthException;
use HongaYetu\AuthSDK\HongaAuthClient;
use HongaYetu\AuthSDK\Support\HongaLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
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
        $mode = $request->get('mode', 'login');

        HongaLogger::debug('Starting OAuth redirect', [
            'mode' => $mode,
            'state' => $state,
        ]);

        Session::put('honga_auth_state', $state);

        $redirectUri = route('honga-auth.callback');

        // If register mode, redirect to Honga registration page
        if ($mode === 'register') {
            $registrationUrl = config('honga-auth.routes.registration_url');

            if ($registrationUrl) {
                $continueUrl = $this->client->getAuthorizationUrl($redirectUri, $state);

                HongaLogger::debug('Redirecting to registration URL', [
                    'registration_url' => $registrationUrl,
                ]);

                return redirect()->away($registrationUrl.'?continue='.urlencode($continueUrl));
            }
        }

        $url = $this->client->getAuthorizationUrl($redirectUri, $state);

        HongaLogger::debug('Redirecting to authorization URL', [
            'url' => $url,
        ]);

        return redirect()->away($url);
    }

    /**
     * Handle OAuth callback from Honga Yetu
     */
    public function callback(Request $request): RedirectResponse
    {
        HongaLogger::debug('OAuth callback received', [
            'has_error' => $request->has('error'),
            'has_code' => $request->has('code'),
            'has_state' => $request->has('state'),
        ]);

        if ($request->has('error')) {
            HongaLogger::error('OAuth error received', [
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
            HongaLogger::warning('Invalid state parameter', [
                'received_state' => $state,
                'expected_state' => $expectedState,
            ]);

            return redirect()
                ->route(config('honga-auth.routes.login_route', 'login'))
                ->with('error', 'Estado de sessão inválido');
        }

        $code = $request->get('code');

        if (! $code) {
            HongaLogger::warning('No authorization code provided');

            return redirect()
                ->route(config('honga-auth.routes.login_route', 'login'))
                ->with('error', 'Código de autorização não fornecido');
        }

        try {
            $redirectUri = route('honga-auth.callback');
            $tokenData = $this->client->exchangeCodeForToken($code, $redirectUri);

            $userData = $tokenData['user'] ?? [];

            if (empty($userData)) {
                HongaLogger::error('No user data in token response');
                throw new HongaAuthException('Dados do utilizador não disponíveis');
            }

            HongaLogger::debug('User data received', [
                'honga_user_id' => $userData['id'] ?? null,
                'email' => $userData['email'] ?? null,
            ]);

            $userModel = config('honga-auth.user_model');
            $user = $userModel::findByHongaUser($userData);

            // User not found - must register first
            if (! $user) {
                HongaLogger::info('User not found, redirect to register', [
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

            HongaLogger::info('User authenticated successfully', [
                'local_user_id' => $user->id,
                'honga_user_id' => $userData['id'] ?? null,
            ]);

            // Register session for SSO logout tracking
            if (! empty($tokenData['honga_session_id'])) {
                Session::put('honga_session_id', $tokenData['honga_session_id']);

                $this->client->registerSession(
                    $tokenData['access_token'],
                    $tokenData['honga_session_id'],
                    session()->getId()
                );

                HongaLogger::info('Session registered for SSO logout', [
                    'local_user_id' => $user->id,
                    'honga_session_id' => $tokenData['honga_session_id'],
                    'client_session_id' => session()->getId(),
                ]);
            }

            return redirect()->intended(
                config('honga-auth.routes.home_route', '/')
            );

        } catch (HongaAuthException $e) {
            HongaLogger::error('Token exchange failed', [
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
        HongaLogger::debug('Logout initiated');

        $token = Session::pull('honga_access_token');

        if ($token) {
            try {
                $this->client->revokeToken($token);
                HongaLogger::info('Token revoked successfully');
            } catch (\Exception $e) {
                HongaLogger::warning('Failed to revoke token', [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        Session::forget(['honga_access_token', 'honga_token_expires_at', 'honga_session_id']);
        Auth::logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        HongaLogger::info('Logout completed');

        return redirect()->route(config('honga-auth.routes.login_route', 'login'));
    }

    /**
     * Silent logout endpoint for front-channel logout (iframe)
     * This is called by Honga Yetu via hidden iframes to silently
     * terminate the session in this app without user interaction
     */
    public function logoutSilent(Request $request): \Illuminate\Http\Response
    {
        $sessionId = $request->get('session_id');

        HongaLogger::debug('Silent logout requested', [
            'session_id' => $sessionId,
        ]);

        if ($sessionId) {
            try {
                // Destroy the specific session
                $sessionHandler = app('session')->getHandler();
                $sessionHandler->destroy($sessionId);

                HongaLogger::info('Silent logout successful', [
                    'session_id' => $sessionId,
                ]);
            } catch (\Exception $e) {
                HongaLogger::warning('Silent logout failed', [
                    'session_id' => $sessionId,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        // Return a 1x1 transparent GIF to make the iframe happy
        $pixel = base64_decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7');

        return response($pixel, 200)
            ->header('Content-Type', 'image/gif')
            ->header('Cache-Control', 'no-cache, no-store, must-revalidate')
            ->header('Pragma', 'no-cache')
            ->header('Expires', '0');
    }
}
