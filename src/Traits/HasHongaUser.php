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
            'honga_profile_version',
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
     * Sync user data from Honga Yetu.
     *
     * When $profileVersion is provided and the local honga_profile_version is
     * greater or equal, the update is skipped entirely (only honga_synced_at is
     * refreshed) — this prevents out-of-order updates between the push path and
     * the reconciliation path on the central from undoing more recent state.
     */
    public function syncFromHonga(array $data, ?int $profileVersion = null): void
    {
        if (
            $profileVersion !== null
            && $this->hongaTableHasColumn('honga_profile_version')
            && (int) $this->honga_profile_version >= $profileVersion
        ) {
            $this->update(['honga_synced_at' => now()]);

            return;
        }

        $fieldMapping = config('honga-auth.sync_fields', [
            'nome' => 'name',
            'email' => 'email',
            'telefone' => 'telefone',
            'foto_link' => 'avatar',
            'aniversario' => 'data_nascimento',
            'genero' => 'genero',
        ]);

        $updateData = [];

        foreach ($fieldMapping as $hongaField => $localField) {
            if (! array_key_exists($hongaField, $data)) {
                continue;
            }

            $value = $data[$hongaField];

            // Um null da central significa "sem dado", não "apaga o que tens":
            // escrever null por cima partia consumidores com colunas NOT NULL
            // (a Sócia tem users.phone NOT NULL, e um user.updated de uma conta
            // sem telefone rebentava o webhook com 23502).
            if ($value === null) {
                continue;
            }

            // Transform genero: Honga (0,1) → local (string)
            if ($hongaField === 'genero' && $value !== null) {
                $value = $this->transformGenero($value);
            }

            // Avatar via URL - handle separately
            if ($hongaField === 'foto_link' && $value) {
                $this->syncAvatarFromUrl($value);

                continue;
            }

            $updateData[$localField] = $value;
        }

        $updateData['honga_synced_at'] = now();

        if ($profileVersion !== null && $this->hongaTableHasColumn('honga_profile_version')) {
            $updateData['honga_profile_version'] = $profileVersion;
        }

        $this->update($updateData);
    }

    /**
     * Whether the underlying users table actually has the given column.
     * Allows the SDK to behave gracefully on installations that have not yet
     * published the honga_profile_version migration.
     */
    protected function hongaTableHasColumn(string $column): bool
    {
        static $cache = [];
        $table = $this->getTable();
        $key = $table.'.'.$column;
        if (! isset($cache[$key])) {
            $cache[$key] = \Illuminate\Support\Facades\Schema::hasColumn($table, $column);
        }

        return $cache[$key];
    }

    /**
     * Transform Honga genero (0=masculino, 1=feminino) to local string format
     */
    protected function transformGenero(mixed $value): string
    {
        return match ((int) $value) {
            0 => 'masculino',
            1 => 'feminino',
            default => 'nao_informado',
        };
    }

    /**
     * Sync avatar from URL - override in your model if using Media Library
     */
    protected function syncAvatarFromUrl(string $url): void
    {
        // Default implementation - override in your User model
        // if using Spatie Media Library or similar
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
            $user->syncFromHonga($hongaUserData, isset($hongaUserData['profile_version']) ? (int) $hongaUserData['profile_version'] : null);

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
            $user->syncFromHonga($hongaUserData, isset($hongaUserData['profile_version']) ? (int) $hongaUserData['profile_version'] : null);

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
