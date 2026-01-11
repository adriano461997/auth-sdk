<?php

namespace HongaYetu\AuthSDK\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;

class InstallCommand extends Command
{
    protected $signature = 'honga-auth:install
                            {--force : Overwrite existing files}';

    protected $description = 'Install the Honga Auth SDK configuration and migrations';

    public function handle(): int
    {
        $this->info('Installing Honga Auth SDK...');

        $this->publishConfig();
        $this->publishMigrations();
        $this->addEnvVariables();

        $this->info('');
        $this->info('Honga Auth SDK installed successfully!');
        $this->info('');
        $this->info('Next steps:');
        $this->line('  1. Add your credentials to .env file');
        $this->line('  2. Run: php artisan migrate');
        $this->line('  3. Add HasHongaUser trait to your User model');
        $this->info('');

        return self::SUCCESS;
    }

    protected function publishConfig(): void
    {
        $this->info('Publishing configuration...');

        $this->call('vendor:publish', [
            '--tag' => 'honga-auth-config',
            '--force' => $this->option('force'),
        ]);
    }

    protected function publishMigrations(): void
    {
        $this->info('Publishing migrations...');

        $this->call('vendor:publish', [
            '--tag' => 'honga-auth-migrations',
            '--force' => $this->option('force'),
        ]);
    }

    protected function addEnvVariables(): void
    {
        $envPath = base_path('.env');

        if (! File::exists($envPath)) {
            return;
        }

        $envContent = File::get($envPath);

        $variables = [
            'HONGA_AUTH_CLIENT_ID' => '',
            'HONGA_AUTH_CLIENT_SECRET' => '',
            'HONGA_AUTH_URL' => 'https://conta.hongayetu.com',
            'HONGA_WEBHOOK_SECRET' => '',
        ];

        $additions = [];

        foreach ($variables as $key => $default) {
            if (! str_contains($envContent, $key)) {
                $additions[] = "{$key}={$default}";
            }
        }

        if (! empty($additions)) {
            $this->info('Adding environment variables...');

            $envContent .= "\n\n# Honga Yetu Authentication\n";
            $envContent .= implode("\n", $additions);
            $envContent .= "\n";

            File::put($envPath, $envContent);
        }
    }
}
