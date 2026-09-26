<?php

declare(strict_types=1);

namespace Componenta\Auth\Password\Tests;

use Componenta\Auth\Http\Exception\InvalidPayloadException;
use Componenta\Auth\Password\PasswordExtractor;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

final class PasswordExtractorTest extends TestCase
{
    public function testPreservesIdentityWithoutCanonicalizingIt(): void
    {
        $request = (new ServerRequest('POST', '/login'))
            ->withParsedBody([
                'email' => 'User@Example.com',
                'password' => 'secret',
            ]);

        $payload = (new PasswordExtractor())->extract($request);

        self::assertSame('User@Example.com', $payload->identity);
        self::assertSame('secret', $payload->password);
    }

    public function testRejectsWhitespacePaddedIdentityAsIdentityField(): void
    {
        $request = (new ServerRequest('POST', '/login'))
            ->withParsedBody([
                'email' => ' user@example.com ',
                'password' => 'secret',
            ]);

        try {
            (new PasswordExtractor())->extract($request);
            self::fail('Malformed identity must fail.');
        } catch (InvalidPayloadException $exception) {
            self::assertSame('email', $exception->field);
        }
    }
}
