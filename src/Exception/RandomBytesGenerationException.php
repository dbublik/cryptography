<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Exception;

final class RandomBytesGenerationException extends AbstractCryptographyException
{
    public function __construct(string $errorMessage, ?\Throwable $previous = null)
    {
        parent::__construct(
            \sprintf('Failure getting pseudo bytes: %s', $errorMessage),
            previous: $previous,
        );
    }
}
