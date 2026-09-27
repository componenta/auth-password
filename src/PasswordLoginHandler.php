<?php

declare(strict_types=1);

namespace Componenta\Auth\Password;

use Componenta\Auth\AuthenticatorInterface;
use Componenta\Auth\Context;
use Componenta\Auth\ContextInterface;
use Componenta\Auth\Denied\InvalidCredentials;
use Componenta\Auth\DeniedReasonInterface;
use Componenta\Auth\Http\CredentialTransportState;
use Componenta\Auth\Http\DeniedResponseFactoryInterface;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Auth\Session\Http\PreAuthenticationConsumer;
use Componenta\Auth\Session\Http\PreAuthenticationGrantPublisher;
use Componenta\Auth\Session\Http\SessionMetadataExtractorInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class PasswordLoginHandler implements RequestHandlerInterface
{
    public function __construct(
        private PasswordExtractor $extractor,
        private AuthenticatorInterface $authenticator,
        private PreAuthenticationConsumer $preAuthentication,
        private PreAuthenticationGrantPublisher $preAuthenticationPublisher,
        private AuthenticatedSessionIssuer $sessionIssuer,
        private AuthSessionGrantPublisher $sessionPublisher,
        private SessionMetadataExtractorInterface $metadata,
        private DeniedResponseFactoryInterface $deniedResponses,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $payload = $this->extractor->extract($request);

        if ($this->preAuthentication->verify($request) === null) {
            return $this->deniedResponses->create(new InvalidCredentials());
        }

        $result = $this->authenticator->attempt($payload, new Context([
            ServerRequestInterface::class => $request,
            ContextInterface::EXTRACTOR => $this->extractor,
        ]));

        if ($result->subject instanceof DeniedReasonInterface) {
            return $this->deniedResponses->create($result->subject);
        }

        $evidence = $result->evidence
            ?? throw new \LogicException(
                'Successful password authentication must contain evidence.',
            );

        // Allocate/prepare every fallible response object before creating
        // durable authenticated state.
        $response = $this->preAuthenticationPublisher->clear(
            $this->responses->createResponse(204),
        );

        if ($this->preAuthentication->consume($request) === null) {
            return $this->deniedResponses->create(new InvalidCredentials());
        }

        $transportState = $request->getAttribute(
            CredentialTransportState::class,
        );

        if ($transportState instanceof CredentialTransportState) {
            $transportState->discardQueued();
        }

        $grant = $this->sessionIssuer->issue(
            $result->subject,
            $evidence,
            $this->metadata->extract($request),
        );

        if ($grant instanceof DeniedReasonInterface) {
            return $this->preAuthenticationPublisher->clear($this->deniedResponses->create($grant));
        }

        return $this->sessionPublisher->publish(
            $request,
            $response,
            $grant,
        );
    }
}
