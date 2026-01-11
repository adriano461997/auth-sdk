<?php

namespace HongaYetu\AuthSDK\Http\Controllers;

use HongaYetu\AuthSDK\HongaAuthClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;

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

        $webhookSecret = config('honga-auth.webhook_secret');

        if ($webhookSecret && $signature) {
            if (! $this->client->validateWebhookSignature($payload, $signature, $webhookSecret)) {
                Log::warning('HongaAuth: Invalid webhook signature');

                return response()->json(['error' => 'Invalid signature'], 401);
            }
        }

        $data = json_decode($payload, true);

        Log::info('HongaAuth: Webhook received', [
            'event' => $eventType,
            'honga_user_id' => $data['honga_user_id'] ?? null,
        ]);

        return match ($eventType) {
            'user.updated' => $this->handleUserUpdated($data),
            'user.deleted' => $this->handleUserDeleted($data),
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

        if (! $hongaUserId) {
            return response()->json(['error' => 'Missing honga_user_id'], 400);
        }

        $userModel = config('honga-auth.user_model');

        if (! $userModel || ! class_exists($userModel)) {
            Log::error('HongaAuth: User model not configured');

            return response()->json(['error' => 'User model not configured'], 500);
        }

        $user = $userModel::where('honga_user_id', $hongaUserId)->first();

        if (! $user) {
            Log::info('HongaAuth: User not found for sync', ['honga_user_id' => $hongaUserId]);

            return response()->json(['status' => 'user_not_found']);
        }

        if (method_exists($user, 'syncFromHonga')) {
            $user->syncFromHonga($data['data'] ?? []);
        }

        Log::info('HongaAuth: User synced', [
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

        if (! $hongaUserId) {
            return response()->json(['error' => 'Missing honga_user_id'], 400);
        }

        $userModel = config('honga-auth.user_model');

        if (! $userModel || ! class_exists($userModel)) {
            return response()->json(['error' => 'User model not configured'], 500);
        }

        $user = $userModel::where('honga_user_id', $hongaUserId)->first();

        if ($user && method_exists($user, 'unlinkFromHonga')) {
            $user->unlinkFromHonga();
        }

        Log::info('HongaAuth: User unlinked due to deletion', [
            'honga_user_id' => $hongaUserId,
        ]);

        return response()->json(['status' => 'ok']);
    }

    /**
     * Handle session.revoked event
     */
    protected function handleSessionRevoked(array $data): JsonResponse
    {
        $hongaUserId = $data['honga_user_id'] ?? null;

        Log::info('HongaAuth: Session revoked', [
            'honga_user_id' => $hongaUserId,
            'reason' => $data['reason'] ?? 'unknown',
        ]);

        return response()->json(['status' => 'ok']);
    }
}
