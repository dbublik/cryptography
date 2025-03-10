<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests\OpenSsl;

use DBublik\Cryptography\OpenSsl\Value;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Value::class)]
final class ValueTest extends TestCase
{
    public function testConstructor(): void
    {
        $value = new Value(
            value: 'text',
            initializationVector: 'vector',
            authenticationTag: 'tag',
        );

        self::assertSame('text', $value->value);
        self::assertSame('vector', $value->initializationVector);
        self::assertSame('tag', $value->authenticationTag);
    }

    /**
     * @param non-empty-string $vector
     * @param non-empty-string $tag
     */
    #[DataProvider('provideConstructorException')]
    public function testConstructorException(string $vector, string $tag): void
    {
        $error = null;

        try {
            new Value(
                value: 'text',
                initializationVector: $vector,
                authenticationTag: $tag,
            );
        } catch (\InvalidArgumentException $e) {
            $error = $e;
        }

        self::assertNotNull($error);
    }

    /**
     * @return iterable<array{0: string, 1: string}>
     */
    public static function provideConstructorException(): iterable
    {
        yield ['', 'tag'];

        yield ['vector', ''];
    }
}
