<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Exception;

use DBublik\Cryptography\Algorithm;

final class AlgorithmNotSupportedException extends AbstractCryptographyException
{
    public function __construct(Algorithm $algorithm)
    {
        parent::__construct(
            \sprintf('Algorithm "%s" not supported', $algorithm->value)
        );
    }
}
