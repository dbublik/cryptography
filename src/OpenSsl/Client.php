<?php

declare(strict_types=1);

namespace DBublik\Cryptography\OpenSsl;

use DBublik\Cryptography\Algorithm;
use DBublik\Cryptography\Exception\AlgorithmNotSupportedException;
use DBublik\Cryptography\Exception\DecryptionFailureException;
use DBublik\Cryptography\Exception\EncryptionFailureException;
use DBublik\Cryptography\Exception\RandomBytesGenerationException;

/**
 * @internal
 */
final readonly class Client
{
    private const AUTHENTICATION_TAG_LENGTH = 16;

    public function __construct(
        /** @var non-empty-string */
        #[\SensitiveParameter]
        private string $secretKey,
        private Algorithm $algorithm = Algorithm::Aes256Gcm,
    ) {}

    /**
     * @return positive-int
     *
     * @throws AlgorithmNotSupportedException
     */
    public function getAlgorithmLength(): int
    {
        /** @var false|positive-int $length */
        $length = openssl_cipher_iv_length($this->algorithm->value);

        // @infection-ignore-all
        if (false === $length) {
            // @codeCoverageIgnoreStart
            throw new AlgorithmNotSupportedException($this->algorithm);
            // @codeCoverageIgnoreEnd
        }

        return $length;
    }

    /**
     * @return positive-int
     */
    public function getAuthenticationTagLength(): int
    {
        return self::AUTHENTICATION_TAG_LENGTH;
    }

    /**
     * @return non-empty-string
     *
     * @throws AlgorithmNotSupportedException
     * @throws RandomBytesGenerationException
     */
    public function getAlgorithmRandomBytes(): string
    {
        return $this->getRandomBytes($this->getAlgorithmLength());
    }

    /**
     * @return non-empty-string
     *
     * @throws RandomBytesGenerationException
     */
    public function getAuthenticationTagRandomBytes(): string
    {
        return $this->getRandomBytes($this->getAuthenticationTagLength());
    }

    /**
     * @param positive-int $length
     *
     * @return non-empty-string
     *
     * @throws RandomBytesGenerationException
     */
    public function getRandomBytes(int $length): string
    {
        try {
            $pseudoBytes = openssl_random_pseudo_bytes(length: $length, strong_result: $strongResult);
        } catch (\Throwable $e) {
            throw new RandomBytesGenerationException($e->getMessage(), previous: $e);
        }

        // @infection-ignore-all
        if (false === $strongResult) {
            // @codeCoverageIgnoreStart
            throw new RandomBytesGenerationException($this->getLastError());
            // @codeCoverageIgnoreEnd
        }

        // @phpstan-ignore return.type
        return $pseudoBytes;
    }

    /**
     * @throws AlgorithmNotSupportedException
     * @throws EncryptionFailureException
     * @throws RandomBytesGenerationException
     */
    public function encrypt(#[\SensitiveParameter] string $plainText): Value
    {
        $initializationVector = $this->getAlgorithmRandomBytes();
        $authenticationTag = $this->getAuthenticationTagRandomBytes();

        $encryptedText = openssl_encrypt(
            data: $plainText,
            cipher_algo: $this->algorithm->value,
            passphrase: $this->secretKey,
            options: OPENSSL_RAW_DATA,
            iv: $initializationVector,
            tag: $authenticationTag
        );

        // @infection-ignore-all
        if (false === $encryptedText) {
            // @codeCoverageIgnoreStart
            throw new EncryptionFailureException($this->getLastError());
            // @codeCoverageIgnoreEnd
        }

        return new Value($encryptedText, $initializationVector, $authenticationTag);
    }

    /**
     * @throws DecryptionFailureException
     */
    public function decrypt(Value $value): string
    {
        $plaintText = openssl_decrypt(
            data: $value->value,
            cipher_algo: $this->algorithm->value,
            passphrase: $this->secretKey,
            options: OPENSSL_RAW_DATA,
            iv: $value->initializationVector,
            tag: $value->authenticationTag
        );

        if (false === $plaintText) {
            throw new DecryptionFailureException($this->getLastError());
        }

        return $plaintText;
    }

    public function getLastError(): string
    {
        $error = openssl_error_string();

        return false !== $error ? $error : '-';
    }
}
