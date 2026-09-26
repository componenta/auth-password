<?php

declare(strict_types=1);

namespace Componenta\Auth\Password;

final readonly class PasswordPayload implements \JsonSerializable
{
    public function __construct(
        public string $identity,
        #[\SensitiveParameter]
        public string $password,
    ) {
        if (
            $this->identity === ''
            || strlen($this->identity) > 320
            || trim($this->identity) !== $this->identity
            || preg_match('/[\x00-\x1F\x7F]/', $this->identity) === 1
        ) {
            throw new \InvalidArgumentException(
                'Password identity is invalid.',
            );
        }

        if ($this->password === '' || strlen($this->password) > 4096) {
            throw new \InvalidArgumentException(
                'Password credential is invalid.',
            );
        }
    }

    /** @return array{identity: string, password: string} */
    public function __debugInfo(): array
    {
        return [
            'identity' => $this->identity,
            'password' => '[REDACTED]',
        ];
    }

    /** @return array{identity: string, password: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
