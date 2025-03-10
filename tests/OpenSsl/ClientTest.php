<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests\OpenSsl;

use DBublik\Cryptography\Algorithm;
use DBublik\Cryptography\Exception\DecryptionFailureException;
use DBublik\Cryptography\Exception\RandomBytesGenerationException;
use DBublik\Cryptography\OpenSsl\Client;
use DBublik\Cryptography\OpenSsl\Value;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Client::class)]
final class ClientTest extends TestCase
{
    public function testConstructor(): void
    {
        $secretKey = 'secret_key';
        $defaultAlgorithm = Algorithm::Aes256Gcm;

        $client = new Client($secretKey);

        self::assertSame($secretKey, (new \ReflectionProperty($client, 'secretKey'))->getValue($client));
        self::assertSame($defaultAlgorithm, (new \ReflectionProperty($client, 'algorithm'))->getValue($client));
    }

    #[DataProvider('provideGetAlgorithmLength')]
    public function testGetAlgorithmLength(Algorithm $algorithm): void
    {
        $client = $this->createClient($algorithm);

        $length = $client->getAlgorithmLength();

        self::assertSame(12, $length);
    }

    /**
     * @return iterable<array{0: Algorithm}>
     */
    public static function provideGetAlgorithmLength(): iterable
    {
        foreach (Algorithm::cases() as $algorithm) {
            yield [$algorithm];
        }
    }

    public function testGetAuthenticationTagLength(): void
    {
        $client = $this->createClient();

        $length = $client->getAuthenticationTagLength();

        self::assertSame(16, $length);
    }

    public function testGetAlgorithmRandomBytes(): void
    {
        $client = $this->createClient();

        $randomBytes = $client->getAlgorithmRandomBytes();

        self::assertSame(12, \strlen($randomBytes));
    }

    public function testGetAuthenticationTagRandomBytes(): void
    {
        $client = $this->createClient();

        $randomBytes = $client->getAuthenticationTagRandomBytes();

        self::assertSame(16, \strlen($randomBytes));
    }

    /**
     * @param positive-int $length
     *
     * @throws RandomBytesGenerationException
     */
    #[DataProvider('provideGetRandomBytes')]
    public function testGetRandomBytes(int $length): void
    {
        $client = $this->createClient();

        $randomBytes = $client->getRandomBytes($length);

        self::assertSame($length, \strlen($randomBytes));
    }

    /**
     * @return iterable<array{0: int}>
     */
    public static function provideGetRandomBytes(): iterable
    {
        yield [1];

        yield [7];

        yield [50];

        yield [99];
    }

    public function testGetRandomBytesException(): void
    {
        $client = $this->createClient();

        $this->expectExceptionObject(
            new RandomBytesGenerationException(
                'openssl_random_pseudo_bytes(): Argument #1 ($length) must be greater than 0'
            )
        );

        // @phpstan-ignore argument.type
        $client->getRandomBytes(0);
    }

    public function testEncryptEmptyText(): void
    {
        $client = $this->createClient();

        $value = $client->encrypt('');

        self::assertSame('', $value->value);
    }

    #[DataProvider('provideEncrypt')]
    public function testEncrypt(Algorithm $algorithm, string $text): void
    {
        $client = $this->createClient($algorithm);

        $value = $client->encrypt($text);

        self::assertNotSame('', $value->value);
        $tag = $value->authenticationTag;
        self::assertSame(
            openssl_encrypt(
                data: $text,
                cipher_algo: $algorithm->value,
                passphrase: 'sc',
                options: OPENSSL_RAW_DATA,
                iv: $value->initializationVector,
                tag: $tag,
            ),
            $value->value
        );
    }

    /**
     * @return iterable<array{0: Algorithm, 1: non-empty-string}>
     */
    public static function provideEncrypt(): iterable
    {
        foreach (Algorithm::cases() as $algorithm) {
            yield [$algorithm, '-'];

            yield [$algorithm, '09123'];

            yield [$algorithm, 'some text and some other text'];

            yield [$algorithm, 'D(&D^V#*)@)*&B@)#&*@)*#&!(*#&_@)(HU!B)(!@U)EB(@U!'];
        }
    }

    #[DataProvider('provideEncrypt')]
    public function testDecrypt(Algorithm $algorithm, string $text): void
    {
        $client = $this->createClient($algorithm);
        $algorithmRandomBytes = $client->getAlgorithmRandomBytes();
        $authenticationTagRandomBytes = $client->getAuthenticationTagRandomBytes();
        $encryptedText = openssl_encrypt(
            data: $text,
            cipher_algo: $algorithm->value,
            passphrase: 'sc',
            options: OPENSSL_RAW_DATA,
            iv: $algorithmRandomBytes,
            tag: $authenticationTagRandomBytes,
        );

        /** @phpstan-ignore argument.type */
        $value = new Value($encryptedText, $algorithmRandomBytes, $authenticationTagRandomBytes);

        $decryptedText = $client->decrypt($value);

        self::assertSame($text, $decryptedText);
    }

    public function testDecryptException(): void
    {
        $client = $this->createClient();
        $value = new Value('', '-', '-');

        $this->expectExceptionObject(
            new DecryptionFailureException('-')
        );

        $client->decrypt($value);
    }

    public function testGetLastError(): void
    {
        $client = $this->createClient();

        $error = $client->getLastError();

        self::assertSame('-', $error);
    }

    private function createClient(Algorithm $algorithm = Algorithm::Aes256Gcm): Client
    {
        return new Client('sc', $algorithm);
    }
}
