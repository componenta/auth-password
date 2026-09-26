<?php

declare(strict_types=1);

namespace Componenta\Auth\Password\PasswordReset;

use Componenta\Auth\Token\TokenPurpose;
use Componenta\Auth\Token\TokenRequest;
use Componenta\Auth\Token\TokenRequestQueueInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class ForgotPasswordHandler implements RequestHandlerInterface
{
    public function __construct(
        private TokenRequestQueueInterface $queue,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $body = $request->getParsedBody();
        $identity = is_array($body) ? ($body['email'] ?? null) : null;

        if (
            !is_string($identity)
            || $identity === ''
            || strlen($identity) > 320
            || trim($identity) !== $identity
            || preg_match('/[\x00-\x1F\x7F]/', $identity) === 1
        ) {
            return $this->json(400, ['error' => 'invalid_email']);
        }

        $response = $this->json(200, [
            'message' => 'If the account exists, a reset link has been sent.',
        ]);

        $this->queue->enqueue(new TokenRequest(
            identity: $identity,
            purpose: new TokenPurpose('password_reset'),
        ));

        return $response;
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
