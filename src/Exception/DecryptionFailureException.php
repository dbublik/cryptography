<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Exception;

final class DecryptionFailureException extends AbstractCryptographyException
{
    public function __construct(string $errorMessage)
    {
        parent::__construct(
            \sprintf('Failure decrypting text: %s', $errorMessage)
        );
    }
}
