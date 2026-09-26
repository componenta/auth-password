<?php

declare(strict_types=1);

namespace Componenta\Auth\Password\PasswordReset;

enum PasswordResetResult
{
    case Success;
    case InvalidToken;
    case PasswordRejected;
}
