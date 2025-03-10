<?php

declare(strict_types=1);

namespace DBublik\Cryptography;

use DBublik\Cryptography\Exception\AlgorithmNotSupportedException;
use DBublik\Cryptography\Exception\DecryptionFailureException;
use DBublik\Cryptography\Exception\EncryptionFailureException;
use DBublik\Cryptography\Exception\RandomBytesGenerationException;
use DBublik\Cryptography\OpenSsl\Client;
use DBublik\Cryptography\OpenSsl\Hasher;

/**
 * @api
 */
final readonly class Encrypter
{
    public function __construct(
        private Client $client,
        private Hasher $hasher,
    ) {}

    /**
     * @param non-empty-string $secretKey
     */
    public static function create(#[\SensitiveParameter] string $secretKey): self
    {
        return new self(new Client($secretKey), new Hasher());
    }

    /**
     * @return non-empty-string
     *
     * @throws AlgorithmNotSupportedException
     * @throws EncryptionFailureException
     * @throws RandomBytesGenerationException
     */
    public function encrypt(#[\SensitiveParameter] string $plainText): string
    {
        $value = $this->client->encrypt($plainText);

        return $this->hasher->hash($value);
    }

    /**
     * @param non-empty-string $encryptedText
     *
     * @throws AlgorithmNotSupportedException
     * @throws DecryptionFailureException
     */
    public function decrypt(string $encryptedText): string
    {
        $value = $this->hasher->unhash(
            $encryptedText,
            $this->client->getAlgorithmLength(),
            $this->client->getAuthenticationTagLength()
        );

        return $this->client->decrypt($value);
    }
}
