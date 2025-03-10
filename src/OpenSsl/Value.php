<?php

declare(strict_types=1);

namespace DBublik\Cryptography\OpenSsl;

/**
 * @internal
 */
final readonly class Value
{
    public function __construct(
        #[\SensitiveParameter]
        public string $value,
        /** @var non-empty-string */
        public string $initializationVector,
        /** @var non-empty-string */
        public string $authenticationTag,
    ) {
        if ('' === $this->initializationVector) {
            throw new \InvalidArgumentException('initializationVector cannot be empty');
        }
        if ('' === $this->authenticationTag) {
            throw new \InvalidArgumentException('AuthenticationTag cannot be empty');
        }
    }
}
