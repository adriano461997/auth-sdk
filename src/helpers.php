<?php

use HongaYetu\AuthSDK\Facades\HongaAuth;

if (!function_exists('honga_logout_url')) {
    /**
     * Get the SSO logout URL with continue parameter
     *
     * @param string|null $continueUrl URL to redirect after logout
     * @return string The SSO logout URL
     */
    function honga_logout_url(?string $continueUrl = null): string
    {
        return HongaAuth::getSsoLogoutUrl($continueUrl);
    }
}

if (!function_exists('honga_auth_url')) {
    /**
     * Get the Honga Auth base URL
     *
     * @return string The base URL
     */
    function honga_auth_url(): string
    {
        return HongaAuth::getBaseUrl();
    }
}
