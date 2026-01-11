<?php

namespace HongaYetu\AuthSDK\Traits;

use Illuminate\Database\Eloquent\Builder;

trait HasHongaUser
{
    /**
     * Initialize the trait
     */
    public function initializeHasHongaUser(): void
    {
        $this->fillable = array_merge($this->fillable ?? [], [
            'honga_user_id',
            'honga_synced_at',
        ]);
    }

    /**
     * Check if user is linked to Honga Yetu
     */
    public function isLinkedToHonga(): bool
    {
        return $this->honga_user_id !== null;
    }

    /**
     * Get the Honga Yetu user ID
     */
    public function getHongaUserId(): ?int
    {
        return $this->honga_user_id;
    }

    /**
     * Link this user to a Honga Yetu account
     */
    public function linkToHonga(int $hongaUserId): void
    {
        $this->update([
            'honga_user_id' => $hongaUserId,
            'honga_synced_at' => now(),
        ]);
    }

    /**
     * Unlink from Honga Yetu account
     */
    public function unlinkFromHonga(): void
    {
        $this->update([
            'honga_user_id' => null,
            'honga_synced_at' => null,
        ]);
    }

    /**
     * Sync user data from Honga Yetu
     */
    public function syncFromHonga(array $data): void
    {
        $syncableFields = config('honga-auth.sync_fields', ['nome', 'email', 'telefone', 'foto']);

        $updateData = [];

        foreach ($syncableFields as $field) {
            if (isset($data[$field])) {
                $updateData[$field] = $data[$field];
            }
        }

        $updateData['honga_synced_at'] = now();

        $this->update($updateData);
    }

    /**
     * Scope for users linked to Honga Yetu
     */
    public function scopeLinkedToHonga(Builder $query): Builder
    {
        return $query->whereNotNull('honga_user_id');
    }

    /**
     * Scope for users not linked to Honga Yetu
     */
    public function scopeNotLinkedToHonga(Builder $query): Builder
    {
        return $query->whereNull('honga_user_id');
    }

    /**
     * Scope to find by Honga user ID
     */
    public function scopeByHongaUserId(Builder $query, int $hongaUserId): Builder
    {
        return $query->where('honga_user_id', $hongaUserId);
    }

    /**
     * Find user by Honga Yetu data (for LOGIN - never creates)
     * Returns null if user doesn't exist
     */
    public static function findByHongaUser(array $hongaUserData): ?static
    {
        // First try by honga_user_id
        $user = static::where('honga_user_id', $hongaUserData['id'])->first();

        if ($user) {
            // Sync data on every login
            $user->syncFromHonga($hongaUserData);

            return $user;
        }

        // Try by email or telefone (for users not yet linked)
        $user = static::where('email', $hongaUserData['email'] ?? null)
            ->when($hongaUserData['telefone'] ?? null, function ($query) use ($hongaUserData) {
                $query->orWhere('telefone', $hongaUserData['telefone']);
            })
            ->first();

        if ($user) {
            // Link and sync
            $user->linkToHonga($hongaUserData['id']);
            $user->syncFromHonga($hongaUserData);

            return $user;
        }

        // User not found - must register first
        return null;
    }

    /**
     * Check if a Honga user can login (exists in local system)
     */
    public static function hongaUserExists(array $hongaUserData): bool
    {
        return static::where('honga_user_id', $hongaUserData['id'])
            ->orWhere('email', $hongaUserData['email'] ?? null)
            ->when($hongaUserData['telefone'] ?? null, function ($query) use ($hongaUserData) {
                $query->orWhere('telefone', $hongaUserData['telefone']);
            })
            ->exists();
    }
}
