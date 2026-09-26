<?php

declare(strict_types=1);

namespace Componenta\Auth\Password;

use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationResult;
use Componenta\Auth\AuthenticationStrategyInterface;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Stdlib\PasswordHasher;
use Componenta\Stdlib\PasswordHasherInterface;
use Componenta\Stdlib\PasswordVerifierInterface;

final class PasswordStrategy implements AuthenticationStrategyInterface
{
    private readonly string $dummyHash;

    public function __construct(
        private readonly PasswordIdentityProviderInterface $identities,
        private readonly PasswordHasherInterface&PasswordVerifierInterface $hasher = new PasswordHasher(),
        ?string $dummyHash = null,
    ) {
        $this->dummyHash = $dummyHash
            ?? $this->hasher->hash('componenta-auth-password-dummy');
    }

    #[\Override]
    public function supports(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): bool {
        return $payload instanceof PasswordPayload;
    }

    #[\Override]
    public function attempt(
        #[\SensitiveParameter]
        object $payload,
        #[\SensitiveParameter]
        ContextInterface $context,
    ): AuthenticationResult {
        if (!$payload instanceof PasswordPayload) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        $identity = $this->identities->findByIdentity($payload->identity);
        $hash = $identity === null
            ? $this->dummyHash
            : $identity->passwordHash;
        $valid = $this->hasher->verify(
            $payload->password,
            $hash,
        );

        if ($identity === null || !$valid) {
            return new AuthenticationResult(new InvalidCredentials());
        }

        return new AuthenticationResult(
            subject: $identity,
            evidence: new AuthenticationEvidence(
                methods: ['password'],
                capabilities: ['knowledge'],
            ),
        );
    }
}
