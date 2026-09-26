<?php

declare(strict_types=1);

namespace Componenta\Auth\Password;

interface PasswordHashAwareInterface
{
    public string $passwordHash { get; }
}
