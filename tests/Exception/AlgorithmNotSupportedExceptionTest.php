<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests\Exception;

use DBublik\Cryptography\Algorithm;
use DBublik\Cryptography\Exception\AlgorithmNotSupportedException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(AlgorithmNotSupportedException::class)]
final class AlgorithmNotSupportedExceptionTest extends TestCase
{
    #[DataProvider('provideConstructor')]
    public function testConstructor(Algorithm $algorithm): void
    {
        $exception = new AlgorithmNotSupportedException($algorithm);

        self::assertSame(\sprintf('Algorithm "%s" not supported', $algorithm->value), $exception->getMessage());
        self::assertSame(0, $exception->getCode());
        self::assertNull($exception->getPrevious());
    }

    /**
     * @return iterable<array{0: Algorithm}>
     */
    public static function provideConstructor(): iterable
    {
        foreach (Algorithm::cases() as $algorithm) {
            yield [$algorithm];
        }
    }
}
