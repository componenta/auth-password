<?php

declare(strict_types=1);

namespace Componenta\Auth\Password;

use Componenta\Identity\IdentityInterface;

interface PasswordIdentityProviderInterface
{
    public function findByIdentity(
        string $identity,
    ): null|(IdentityInterface&PasswordHashAwareInterface);
}
