<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests\OpenSsl;

use DBublik\Cryptography\Exception\DecryptionFailureException;
use DBublik\Cryptography\OpenSsl\Hasher;
use DBublik\Cryptography\OpenSsl\Value;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Hasher::class)]
final class HasherTest extends TestCase
{
    #[DataProvider('provideHash')]
    public function testHash(Value $value, string $expectedHash): void
    {
        $hasher = new Hasher();

        $hash = $hasher->hash($value);

        self::assertSame($expectedHash, $hash);
    }

    /**
     * @return iterable<array{0: Value, 1: non-empty-string}>
     */
    public static function provideHash(): iterable
    {
        yield [
            new Value('', 'oxcznpzkcn', '9n237bd'),
            'b3hjem5wemtjbjluMjM3YmQ=',
        ];

        yield [
            new Value('1', 'qwe', 'asd'),
            'cXdlMWFzZA==',
        ];

        yield [
            new Value('V(#&*^V8v30v603', 'B(D)&#BDQ#_(UB#D_(&BD#', ' C*&)#B CN#7TRB0C#)TB*CG)#*7'),
            'QihEKSYjQkRRI18oVUIjRF8oJkJEI1YoIyYqXlY4djMwdjYwMyBDKiYpI0IgQ04jN1RSQjBDIylUQipDRykjKjc=',
        ];
    }

    /**
     * @param non-empty-string $text
     * @param positive-int $algoLength
     * @param positive-int $authTagLength
     * @param non-empty-string $errorMessage
     *
     * @throws DecryptionFailureException
     */
    #[DataProvider('provideUnhashException')]
    public function testUnhashException(string $text, int $algoLength, int $authTagLength, string $errorMessage): void
    {
        $hasher = new Hasher();

        $this->expectExceptionObject(
            new DecryptionFailureException($errorMessage)
        );

        $hasher->unhash($text, $algoLength, $authTagLength);
    }

    /**
     * @return iterable<array{text: string, algoLength: int, authTagLength: int, errorMessage: non-empty-string}>
     */
    public static function provideUnhashException(): iterable
    {
        yield [
            'text' => '-',
            'algoLength' => 0,
            'authTagLength' => 0,
            'errorMessage' => 'Bad value',
        ];

        yield [
            'text' => 'NC)N*&B#)*#',
            'algoLength' => 0,
            'authTagLength' => 0,
            'errorMessage' => 'Bad value',
        ];

        yield [
            'text' => '',
            'algoLength' => 1,
            'authTagLength' => 1,
            'errorMessage' => 'Bad decoded value',
        ];

        yield [
            'text' => 'cXdlcnR5', // base64_encode('qwerty')
            'algoLength' => 3,
            'authTagLength' => 4,
            'errorMessage' => 'Bad decoded value',
        ];

        yield [
            'text' => 'RCkqJkRCIzM=', // base64_encode('D)*&DB#3')
            'algoLength' => 2,
            'authTagLength' => 9,
            'errorMessage' => 'Bad decoded value',
        ];
    }

    /**
     * @param non-empty-string $text
     * @param positive-int $algoLength
     * @param positive-int $authTagLength
     *
     * @throws DecryptionFailureException
     */
    #[DataProvider('provideUnhash')]
    public function testUnhash(string $text, int $algoLength, int $authTagLength, Value $expectedValue): void
    {
        $hasher = new Hasher();

        $value = $hasher->unhash($text, $algoLength, $authTagLength);

        self::assertSame($expectedValue->value, $value->value);
        self::assertSame($expectedValue->initializationVector, $value->initializationVector);
        self::assertSame($expectedValue->authenticationTag, $value->authenticationTag);
    }

    /**
     * @return iterable<
     *     array{text: non-empty-string, algoLength: positive-int, authTagLength: positive-int, expectedValue: Value}
     * >
     */
    public static function provideUnhash(): iterable
    {
        yield [
            'text' => 'cXdlcnR5', // base64_encode('qwerty')
            'algoLength' => 3,
            'authTagLength' => 3,
            'expectedValue' => new Value('', 'qwe', 'rty'),
        ];

        yield [
            'text' => 'cXdlcnR5dQ==', // base64_encode('qwertyu')
            'algoLength' => 3,
            'authTagLength' => 3,
            'expectedValue' => new Value('r', 'qwe', 'tyu'),
        ];

        yield [
            'text' => 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=', // base64_encode('abcdefghijklmnopqrstuvwxyz')
            'algoLength' => 6,
            'authTagLength' => 12,
            'expectedValue' => new Value('ghijklmn', 'abcdef', 'opqrstuvwxyz'),
        ];
    }
}
