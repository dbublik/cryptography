<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Exception;

final class EncryptionFailureException extends AbstractCryptographyException
{
    public function __construct(string $errorMessage)
    {
        parent::__construct(
            \sprintf('Failure encrypting text: %s', $errorMessage)
        );
    }
}
