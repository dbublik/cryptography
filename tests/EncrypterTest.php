<?php

declare(strict_types=1);

namespace DBublik\Cryptography\Tests;

use DBublik\Cryptography\Encrypter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(Encrypter::class)]
final class EncrypterTest extends TestCase
{
    public function testConstructor(): void
    {
        $this->expectExceptionObject(
            new \RuntimeException('Not implemented yet')
        );

        new Encrypter();
    }
}
