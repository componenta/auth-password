<?php

declare(strict_types=1);

namespace Componenta\Auth\Password\Tests;

use Componenta\Auth\Password\PasswordReset\PasswordResetResult;
use Componenta\Auth\Password\PasswordReset\PasswordResetServiceInterface;
use Componenta\Auth\Password\PasswordReset\ResetPasswordHandler;
use Componenta\Auth\Token\TokenCredential;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;

final class PasswordResetHandlerTest extends TestCase
{
    public function testDelegatesValidatedCredentialToApplicationResetService(): void
    {
        $credential = TokenCredential::fromBytes(str_repeat('a', 32));
        $service = $this->createMock(PasswordResetServiceInterface::class);
        $service->expects(self::once())
            ->method('reset')
            ->with(
                self::callback(
                    static fn(TokenCredential $value): bool =>
                        $value->toString() === $credential->toString(),
                ),
                'new-password',
            )
            ->willReturn(PasswordResetResult::Success);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturnCallback(
            static fn(int $status): Response => new Response($status),
        );
        $request = (new ServerRequest('POST', '/reset'))
            ->withParsedBody([
                'token' => $credential->toString(),
                'password' => 'new-password',
                'passwordConfirmation' => 'new-password',
            ]);

        $response = (new ResetPasswordHandler($service, $responses))
            ->handle($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }
}
