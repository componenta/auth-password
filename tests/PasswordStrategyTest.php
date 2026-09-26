<?php

declare(strict_types=1);

namespace Componenta\Auth\Password\Tests;

use Componenta\Auth\Context;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\Password\PasswordHashAwareInterface;
use Componenta\Auth\Password\PasswordIdentityProviderInterface;
use Componenta\Auth\Password\PasswordPayload;
use Componenta\Auth\Password\PasswordStrategy;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\Uuid;
use Componenta\Identity\UuidInterface;
use Componenta\Stdlib\PasswordHasherInterface;
use Componenta\Stdlib\PasswordVerifierInterface;
use PHPUnit\Framework\TestCase;

final class PasswordStrategyTest extends TestCase
{
    public function testSuccessCarriesExplicitPasswordEvidence(): void
    {
        $identity = new PasswordIdentityFixture();
        $strategy = new PasswordStrategy(
            new PasswordProviderFixture($identity),
            new PasswordVerifierFixture(),
            'dummy',
        );

        $result = $strategy->attempt(
            new PasswordPayload('user@example.com', 'secret'),
            new Context(),
        );

        self::assertSame($identity, $result->subject);
        self::assertSame(['password'], $result->evidence?->methods);
        self::assertSame(['knowledge'], $result->evidence?->capabilities);
    }

    public function testUnknownIdentityStillRunsDummyVerification(): void
    {
        $verifier = new PasswordVerifierFixture();
        $strategy = new PasswordStrategy(
            new PasswordProviderFixture(null),
            $verifier,
            'dummy',
        );

        $result = $strategy->attempt(
            new PasswordPayload('unknown@example.com', 'wrong'),
            new Context(),
        );

        self::assertInstanceOf(InvalidCredentials::class, $result->subject);
        self::assertSame(1, $verifier->verifications);
        self::assertSame('dummy', $verifier->lastHash);
    }
}

final class PasswordIdentityFixture implements
    IdentityInterface,
    PasswordHashAwareInterface
{
    public string $passwordHash {
        get => 'real-hash';
    }

    public UuidInterface $uuid {
        get => Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
    }
}

final readonly class PasswordProviderFixture implements
    PasswordIdentityProviderInterface
{
    public function __construct(
        private ?PasswordIdentityFixture $identity,
    ) {}

    public function findByIdentity(
        string $identity,
    ): null|(IdentityInterface&PasswordHashAwareInterface) {
        return $this->identity;
    }
}

final class PasswordVerifierFixture implements
    PasswordHasherInterface,
    PasswordVerifierInterface
{
    public int $verifications = 0;
    public ?string $lastHash = null;

    public function hash(string $password): string
    {
        return 'dummy';
    }

    public function verify(string $password, string $hash): bool
    {
        ++$this->verifications;
        $this->lastHash = $hash;

        return $password === 'secret' && $hash === 'real-hash';
    }
}
