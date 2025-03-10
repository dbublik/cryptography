<?php

declare(strict_types=1);

namespace DBublik\Cryptography\OpenSsl;

use DBublik\Cryptography\Exception\DecryptionFailureException;

/**
 * @internal
 */
final readonly class Hasher
{
    /**
     * @return non-empty-string
     */
    public function hash(Value $value): string
    {
        return base64_encode($value->initializationVector . $value->value . $value->authenticationTag);
    }

    /**
     * @param non-empty-string $text
     * @param positive-int $algorithmLength
     * @param positive-int $authenticationTagLength
     *
     * @throws DecryptionFailureException
     */
    public function unhash(string $text, int $algorithmLength, int $authenticationTagLength): Value
    {
        if (false === $decodedValue = base64_decode($text, true)) {
            throw new DecryptionFailureException('Bad value');
        }

        if (\strlen($decodedValue) < ($algorithmLength + $authenticationTagLength)) {
            throw new DecryptionFailureException('Bad decoded value');
        }

        /** @var non-empty-string $initializationVector */
        $initializationVector = substr($decodedValue, 0, $algorithmLength);

        /** @var non-falsy-string $authenticationTag */
        $authenticationTag = substr($decodedValue, -$authenticationTagLength);

        $value = substr($decodedValue, $algorithmLength, -$authenticationTagLength);

        return new Value(
            value: $value,
            initializationVector: $initializationVector,
            authenticationTag: $authenticationTag,
        );
    }
}
