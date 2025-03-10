<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests\Exception;

use DBublik\Cryptography\Exception\EncryptionFailureException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(EncryptionFailureException::class)]
final class EncryptionFailureExceptionTest extends TestCase
{
    #[DataProvider('provideConstructor')]
    public function testConstructor(string $errorMessage): void
    {
        $exception = new EncryptionFailureException($errorMessage);

        self::assertSame(\sprintf('Failure encrypting text: %s', $errorMessage), $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    /**
     * @return iterable<array{0: string}>
     */
    public static function provideConstructor(): iterable
    {
        yield [''];

        yield ['-'];

        yield ['some error'];
    }
}
