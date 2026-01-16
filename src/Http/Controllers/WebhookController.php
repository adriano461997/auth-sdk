<?php

namespace HongaYetu\AuthSDK\Http\Controllers;

use HongaYetu\AuthSDK\HongaAuthClient;
use HongaYetu\AuthSDK\Support\HongaLogger;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class WebhookController extends Controller
{
    protected HongaAuthClient $client;

    public function __construct(HongaAuthClient $client)
    {
        $this->client = $client;
    }

    /**
     * Handle incoming webhook from Honga Yetu
     */
    public function handle(Request $request): JsonResponse
    {
        $payload = $request->getContent();
        $signature = $request->header('X-Honga-Signature');
        $eventType = $request->header('X-Honga-Event');

        HongaLogger::debug('Webhook received', [
            'event' => $eventType,
            'has_signature' => ! empty($signature),
        ]);

        $webhookSecret = config('honga-auth.webhook_secret');

        if ($webhookSecret && $signature) {
            if (! $this->client->validateWebhookSignature($payload, $signature, $webhookSecret)) {
                HongaLogger::warning('Invalid webhook signature');

                return response()->json(['error' => 'Invalid signature'], 401);
            }
            HongaLogger::debug('Webhook signature validated');
        }

        $data = json_decode($payload, true);

        HongaLogger::info('Processing webhook', [
            'event' => $eventType,
            'honga_user_id' => $data['honga_user_id'] ?? null,
        ]);

        return match ($eventType) {
            'user.updated' => $this->handleUserUpdated($data),
            'user.deleted' => $this->handleUserDeleted($data),
            'user.logout' => $this->handleUserLogout($data),
            'session.revoked' => $this->handleSessionRevoked($data),
            default => response()->json(['status' => 'ignored']),
        };
    }

    /**
     * Handle user.updated event
     */
    protected function handleUserUpdated(array $data): JsonResponse
    {
        $hongaUserId = $data['honga_user_id'] ?? null;

        HongaLogger::debug('Handling user.updated event', [
            'honga_user_id' => $hongaUserId,
        ]);

        if (! $hongaUserId) {
            HongaLogger::warning('user.updated missing honga_user_id');

            return response()->json(['error' => 'Missing honga_user_id'], 400);
        }

        $userModel = config('honga-auth.user_model');

        if (! $userModel || ! class_exists($userModel)) {
            HongaLogger::error('User model not configured');

            return response()->json(['error' => 'User model not configured'], 500);
        }

        $user = $userModel::where('honga_user_id', $hongaUserId)->first();

        if (! $user) {
            HongaLogger::info('User not found for sync', ['honga_user_id' => $hongaUserId]);

            return response()->json(['status' => 'user_not_found']);
        }

        if (method_exists($user, 'syncFromHonga')) {
            $user->syncFromHonga($data['data'] ?? []);
        }

        HongaLogger::info('User synced successfully', [
            'local_user_id' => $user->id,
            'honga_user_id' => $hongaUserId,
        ]);

        return response()->json(['status' => 'ok']);
    }

    /**
     * Handle user.deleted event
     */
    protected function handleUserDeleted(array $data): JsonResponse
    {
        $hongaUserId = $data['honga_user_id'] ?? null;

        HongaLogger::debug('Handling user.deleted event', [
            'honga_user_id' => $hongaUserId,
        ]);

        if (! $hongaUserId) {
            HongaLogger::warning('user.deleted missing honga_user_id');

            return response()->json(['error' => 'Missing honga_user_id'], 400);
        }

        $userModel = config('honga-auth.user_model');

        if (! $userModel || ! class_exists($userModel)) {
            HongaLogger::error('User model not configured');

            return response()->json(['error' => 'User model not configured'], 500);
        }

        $user = $userModel::where('honga_user_id', $hongaUserId)->first();

        if ($user && method_exists($user, 'unlinkFromHonga')) {
            $user->unlinkFromHonga();
        }

        HongaLogger::info('User unlinked due to deletion', [
            'honga_user_id' => $hongaUserId,
        ]);

        return response()->json(['status' => 'ok']);
    }

    /**
     * Handle user.logout event - SSO logout
     */
    protected function handleUserLogout(array $data): JsonResponse
    {
        $clientSessionId = $data['client_session_id'] ?? null;
        $hongaUserId = $data['honga_user_id'] ?? null;

        HongaLogger::debug('Handling user.logout event (SSO logout)', [
            'honga_user_id' => $hongaUserId,
            'client_session_id' => $clientSessionId,
        ]);

        if (! $clientSessionId) {
            HongaLogger::warning('SSO logout missing session ID');

            return response()->json(['error' => 'Missing session ID'], 400);
        }

        try {
            // Destroy the session
            $sessionHandler = app('session')->getHandler();
            $sessionHandler->destroy($clientSessionId);

            HongaLogger::info('Session destroyed via SSO logout', [
                'honga_user_id' => $hongaUserId,
                'client_session_id' => $clientSessionId,
            ]);

            return response()->json(['status' => 'ok']);
        } catch (\Exception $e) {
            HongaLogger::error('Failed to destroy session', [
                'error' => $e->getMessage(),
                'client_session_id' => $clientSessionId,
            ]);

            return response()->json(['error' => 'Failed to destroy session'], 500);
        }
    }

    /**
     * Handle session.revoked event
     */
    protected function handleSessionRevoked(array $data): JsonResponse
    {
        $hongaUserId = $data['honga_user_id'] ?? null;

        HongaLogger::info('Session revoked', [
            'honga_user_id' => $hongaUserId,
            'reason' => $data['reason'] ?? 'unknown',
        ]);

        return response()->json(['status' => 'ok']);
    }
}
