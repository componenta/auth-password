<?php

declare(strict_types=1);

namespace Componenta\Auth\Password\PasswordReset;

use Componenta\Auth\Token\TokenCredential;

interface PasswordResetServiceInterface
{
    /**
     * Owns the complete reset transition: consume token, enforce password
     * policy, change the password and invalidate pre-reset long-lived grants.
     */
    public function reset(
        #[\SensitiveParameter]
        TokenCredential $credential,
        #[\SensitiveParameter]
        string $newPassword,
    ): PasswordResetResult;
}
