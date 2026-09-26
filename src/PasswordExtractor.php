<?php

declare(strict_types=1);

namespace Componenta\Auth\Password;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Http\PayloadExtractorInterface;
use Psr\Http\Message\ServerRequestInterface;

final readonly class PasswordExtractor implements PayloadExtractorInterface
{
    public function __construct(
        public string $identityField = 'email',
        public string $passwordField = 'password',
    ) {
        foreach ([$this->identityField, $this->passwordField] as $field) {
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_.-]*\z/D', $field) !== 1) {
                throw new \InvalidArgumentException(
                    'Password field name is invalid.',
                );
            }
        }

        if ($this->identityField === $this->passwordField) {
            throw new \InvalidArgumentException(
                'Password field names must differ.',
            );
        }
    }

    #[\Override]
    public function extract(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): PasswordPayload {
        $body = $request->getParsedBody();

        if (!is_array($body)) {
            throw InvalidPayloadException::invalidField('body');
        }

        if (!array_key_exists($this->identityField, $body)) {
            throw InvalidPayloadException::missingField($this->identityField);
        }

        if (!array_key_exists($this->passwordField, $body)) {
            throw InvalidPayloadException::missingField($this->passwordField);
        }

        $identity = $body[$this->identityField];
        $password = $body[$this->passwordField];

        if (
            !is_string($identity)
            || $identity === ''
            || strlen($identity) > 320
            || trim($identity) !== $identity
            || preg_match('/[\x00-\x1F\x7F]/', $identity) === 1
        ) {
            throw InvalidPayloadException::invalidField($this->identityField);
        }

        if (
            !is_string($password)
            || $password === ''
            || strlen($password) > 4096
        ) {
            throw InvalidPayloadException::invalidField($this->passwordField);
        }

        return new PasswordPayload($identity, $password);
    }
}
