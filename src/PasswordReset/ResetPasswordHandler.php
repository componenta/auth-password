<?php

declare(strict_types=1);

namespace Componenta\Auth\Password\PasswordReset;

use Componenta\Auth\Token\TokenCredential;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class ResetPasswordHandler implements RequestHandlerInterface
{
    public function __construct(
        private PasswordResetServiceInterface $reset,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $body = $request->getParsedBody();
        $body = is_array($body) ? $body : [];
        $rawToken = $body['token'] ?? null;
        $password = $body['password'] ?? null;
        $confirmation = $body['passwordConfirmation'] ?? null;
        $errors = [];

        try {
            $credential = is_string($rawToken)
                ? TokenCredential::fromString($rawToken)
                : null;
        } catch (\InvalidArgumentException) {
            $credential = null;
        }

        if ($credential === null) {
            $errors['token'] = ['Token is invalid.'];
        }

        if (
            !is_string($password)
            || $password === ''
            || strlen($password) > 4096
        ) {
            $errors['password'] = ['Password is invalid.'];
        }

        if (!is_string($confirmation) || $confirmation !== $password) {
            $errors['passwordConfirmation'] = ['Passwords do not match.'];
        }

        if ($errors !== []) {
            return $this->json(422, ['errors' => $errors]);
        }

        $success = $this->json(200, [
            'message' => 'Password has been reset successfully.',
        ]);

        /** @var TokenCredential $credential */
        /** @var non-empty-string $password */
        return match ($this->reset->reset($credential, $password)) {
            PasswordResetResult::Success => $success,
            PasswordResetResult::InvalidToken => $this->json(400, [
                'error' => 'invalid_token',
            ]),
            PasswordResetResult::PasswordRejected => $this->json(422, [
                'errors' => [
                    'password' => ['Password does not satisfy policy.'],
                ],
            ]),
        };
    }

    /** @param array<string, mixed> $data */
    private function json(int $status, array $data): ResponseInterface
    {
        $response = $this->responses->createResponse($status);
        $response->getBody()->write(json_encode($data, JSON_THROW_ON_ERROR));

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
