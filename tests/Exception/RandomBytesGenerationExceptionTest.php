<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests\Exception;

use DBublik\Cryptography\Exception\RandomBytesGenerationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(RandomBytesGenerationException::class)]
final class RandomBytesGenerationExceptionTest extends TestCase
{
    #[DataProvider('provideConstructor')]
    public function testConstructor(string $errorMessage, ?\Throwable $previous = null): void
    {
        $exception = new RandomBytesGenerationException($errorMessage, $previous);

        self::assertSame(\sprintf('Failure getting pseudo bytes: %s', $errorMessage), $exception->getMessage());
        self::assertSame(0, $exception->getCode());

        if (null !== $previous) {
            self::assertNotNull($exception->getPrevious());
        } else {
            self::assertNull($exception->getPrevious());
        }
    }

    /**
     * @return iterable<array{0: string, 1: ?\Throwable}>
     */
    public static function provideConstructor(): iterable
    {
        yield ['', null];

        yield ['-', null];

        yield ['some error', null];

        yield ['some error', new \Exception('previous error')];
    }
}
