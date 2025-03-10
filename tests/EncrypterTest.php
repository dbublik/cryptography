<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests;

use DBublik\Cryptography\Algorithm;
use DBublik\Cryptography\Encrypter;
use DBublik\Cryptography\Exception\AlgorithmNotSupportedException;
use DBublik\Cryptography\Exception\DecryptionFailureException;
use DBublik\Cryptography\OpenSsl\Client;
use DBublik\Cryptography\OpenSsl\Hasher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Encrypter::class)]
final class EncrypterTest extends TestCase
{
    public function testConstructor(): void
    {
        $client = new Client('s');
        $hasher = new Hasher();

        $encrypter = new Encrypter($client, $hasher);

        self::assertSame($client, (new \ReflectionProperty($encrypter, 'client'))->getValue($encrypter));
        self::assertSame($hasher, (new \ReflectionProperty($encrypter, 'hasher'))->getValue($encrypter));
    }

    public function testCreate(): void
    {
        $secretKey = 'secret_key';
        $defaultAlgorithm = Algorithm::Aes256Gcm;

        $encrypter = Encrypter::create($secretKey);

        /** @var Client $client */
        $client = (new \ReflectionProperty($encrypter, 'client'))->getValue($encrypter);
        self::assertSame($secretKey, (new \ReflectionProperty($client, 'secretKey'))->getValue($client));
        self::assertSame($defaultAlgorithm, (new \ReflectionProperty($client, 'algorithm'))->getValue($client));
    }

    #[DataProvider('provideEncrypt')]
    public function testEncrypt(string $text): void
    {
        $encrypter = Encrypter::create('sc');

        $encryptedText = $encrypter->encrypt($text);

        self::assertNotSame('', $encryptedText);
    }

    /**
     * @return iterable<array{0: string}>
     */
    public static function provideEncrypt(): iterable
    {
        yield [''];

        yield ['1234567890'];

        yield ['ldkhfbpsidfubsdpfkjwneoubwpefkj'];

        yield ['B)N(&B#)(&#BC)#CBOCI&#93B&B#U)9f7cb#(&BVP*#&0vy)*#O&bo3i78vb03o9'];

        yield ['($*#^@()&%^#%)(*@&#)(*&#)(*@#)&%(@*#&'];
    }

    /**
     * @param non-empty-string $encryptedText
     *
     * @throws AlgorithmNotSupportedException
     * @throws DecryptionFailureException
     */
    #[DataProvider('provideDecrypt')]
    public function testDecrypt(string $encryptedText, string $expectedText): void
    {
        $encrypter = Encrypter::create('sc');

        $decryptedText = $encrypter->decrypt($encryptedText);

        self::assertSame($expectedText, $decryptedText);
    }

    /**
     * @return iterable<array{0: non-empty-string, 1: string}>
     */
    public static function provideDecrypt(): iterable
    {
        yield [
            'XHzux4LPKyf0nUziGIel0Go1W1VO0QSaVH0bUw==',
            '',
        ];

        yield [
            'VfdH4r/SgV16JnLVdeO5xtuoloQbsNlmq1anMzo=',
            'd',
        ];

        yield [
            'iQ3Zx00YbEoPrTOPl36IH6pwByQdDPiJZDFpmLFEaRAoxwQ=',
            'qqwerwr',
        ];

        yield [
            'xRC3ZFORS0FXO9bUrDaHyP/pkPzkcIzckcx2bmKncvxxeW6/knNblAxX',
            '09238273094234',
        ];

        yield [
            'CrbWGQf1rl4yIuS9fJ+RrPtIzQDJuYPbXjCxpZJPyx6laWeeEojdcRZIA346hE69isSurJA30vpauaM=',
            'HD*#)@&#)@D#&Hd0983hd923hd-2po3',
        ];

        yield [
            'MZb4w6z/5hEn4hQbYoxWPd8S0rg9XjBrkfL5lWSJGILk9Tdh4HewFcE3LHNzGWZbeQtXNQ2NvtDEkWJkCBGfGh7tVw==',
            '$*&^$#()&@)#($^#)($@#^)$(&__!^()*^!@$)(',
        ];
    }
}
