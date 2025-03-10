<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests\Exception;

use DBublik\Cryptography\Exception\DecryptionFailureException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(DecryptionFailureException::class)]
final class DecryptionFailureExceptionTest extends TestCase
{
    #[DataProvider('provideConstructor')]
    public function testConstructor(string $errorMessage): void
    {
        $exception = new DecryptionFailureException($errorMessage);

        self::assertSame(\sprintf('Failure decrypting text: %s', $errorMessage), $exception->getMessage());
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
