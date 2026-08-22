<?php

namespace HongaYetu\AuthSDK\Http\Controllers;

use HongaYetu\AuthSDK\HongaAuthClient;
use HongaYetu\AuthSDK\Support\HongaLogger;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

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
        $eventId = $request->header('X-Honga-Event-Id');

        HongaLogger::debug('Webhook received', [
            'event' => $eventType,
            'event_id' => $eventId,
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
        $eventId = $eventId ?: ($data['event_id'] ?? null);
        $eventType = $eventType ?: ($data['event'] ?? null);

        HongaLogger::info('Processing webhook', [
            'event' => $eventType,
            'event_id' => $eventId,
            'honga_user_id' => $data['honga_user_id'] ?? null,
        ]);

        // Idempotency guard: if we have already processed this event_id, return 200
        // immediately so the central marks the delivery as delivered and does not
        // retry. Requires the publishable migration create_webhook_honga_sso_processados.
        if ($eventId && $this->markEventAsProcessed($eventId, (string) $eventType, $data)) {
            // already processed previously
            HongaLogger::info('Webhook duplicate ignored', ['event_id' => $eventId]);

            return response()->json(['status' => 'duplicate']);
        }

        return match ($eventType) {
            'user.updated' => $this->handleUserUpdated($data),
            'user.deleted' => $this->handleUserDeleted($data),
            'user.logout' => $this->handleUserLogout($data),
            'session.revoked' => $this->handleSessionRevoked($data),
            default => response()->json(['status' => 'ignored']),
        };
    }

    /**
     * Tries to record the event_id. Returns true if the event was already processed
     * before (duplicate), false otherwise (first time we see it).
     *
     * If the dedup table does not exist yet (migration not published), behaves as
     * a no-op so the SDK keeps working before consumers run the new migration.
     */
    protected function markEventAsProcessed(string $eventId, string $eventType, array $data): bool
    {
        if (! Schema::hasTable('webhook_honga_sso_processados')) {
            return false;
        }

        try {
            DB::table('webhook_honga_sso_processados')->insert([
                'event_id' => $eventId,
                'event_type' => $eventType,
                'honga_user_id' => $data['honga_user_id'] ?? null,
                'processed_at' => now(),
            ]);

            return false;
        } catch (\Illuminate\Database\QueryException $e) {
            // PK já existe = evento duplicado. O SQLSTATE varia por driver:
            // MySQL agrega tudo em 23000; PostgreSQL usa 23505 (unique_violation).
            // Só com 23000, cada redelivery em Postgres rebentava com 500 e a
            // central reentregava para sempre — o oposto do que o guard promete.
            $sqlstate = $e->errorInfo[0] ?? $e->getCode();
            if (in_array((string) $sqlstate, ['23000', '23505'], true)) {
                return true;
            }
            throw $e;
        }
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

        $profileVersion = isset($data['profile_version']) ? (int) $data['profile_version'] : null;

        if (method_exists($user, 'syncFromHonga')) {
            $user->syncFromHonga($data['data'] ?? [], $profileVersion);
        }

        HongaLogger::info('User synced successfully', [
            'local_user_id' => $user->id,
            'honga_user_id' => $hongaUserId,
            'profile_version' => $profileVersion,
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
