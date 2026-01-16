<?php

namespace HongaYetu\AuthSDK\Support;

use Illuminate\Support\Facades\Log;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

class HongaLogger
{
    protected static ?Logger $logger = null;

    /**
     * Get the logger instance
     */
    protected static function getLogger(): ?Logger
    {
        if (! config('honga-auth.debug', false)) {
            return null;
        }

        if (static::$logger === null) {
            static::$logger = new Logger('honga-auth');
            $logPath = storage_path('logs/honga-auth.log');

            static::$logger->pushHandler(new StreamHandler($logPath, Logger::DEBUG));
        }

        return static::$logger;
    }

    /**
     * Check if debug is enabled
     */
    public static function isEnabled(): bool
    {
        return config('honga-auth.debug', false);
    }

    /**
     * Log debug message
     */
    public static function debug(string $message, array $context = []): void
    {
        $logger = static::getLogger();
        if ($logger) {
            $logger->debug($message, $context);
        }
    }

    /**
     * Log info message
     */
    public static function info(string $message, array $context = []): void
    {
        $logger = static::getLogger();
        if ($logger) {
            $logger->info($message, $context);
        }
    }

    /**
     * Log warning message
     */
    public static function warning(string $message, array $context = []): void
    {
        $logger = static::getLogger();
        if ($logger) {
            $logger->warning($message, $context);
        }
    }

    /**
     * Log error message
     */
    public static function error(string $message, array $context = []): void
    {
        $logger = static::getLogger();
        if ($logger) {
            $logger->error($message, $context);
        }
    }
}
