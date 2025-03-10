# Cryptography

[![PHP Version Requirement](https://img.shields.io/packagist/dependency-v/dbublik/cryptography/php)](https://packagist.org/packages/dbublik/cryptography)
[![License](https://poser.pugx.org/dbublik/cryptography/license)](https://choosealicense.com/licenses/mit/)
[![Tests](https://github.com/dbublik/cryptography/actions/workflows/tests.yaml/badge.svg)](https://github.com/dbublik/cryptography/actions/workflows/tests.yaml)
[![Lint](https://github.com/dbublik/cryptography/actions/workflows/lint.yaml/badge.svg)](https://github.com/dbublik/cryptography/actions/workflows/lint.yaml)
[![Code coverage](https://coveralls.io/repos/github/dbublik/cryptography/badge.svg)](https://coveralls.io/github/dbublik/cryptography)
[![Mutation score](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fdbublik%2Fcryptography%2Fmain)](https://dashboard.stryker-mutator.io/reports/github.com/dbublik/cryptography/main)

Need to encrypt and decrypt strings effortlessly? Encrypter does it for you with just two simple methods.

## Installation

```bash
composer require dbublik/cryptography
```

## Usage

### Initialize encrypter:

```php
use DBublik\Cryptography\Encrypter;

$secretKey = 'your_secret_key';
$encrypter = Encrypter::create($secretKey);
```

or prepare it for a container, e.g. for Symfony:

```php
// config/services.php

namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use DBublik\Cryptography\Encrypter;

return function(ContainerConfigurator $container): void {
    $services = $container->services();

    $services->set(Encrypter::class)
        ->factory([null, 'create'])
        ->args([env('YOUR_SECRET_KEY')]);
};
```

Available encryption algorithms: `aes-128-gcm`, `aes-192-gcm` and `aes-256-gcm` (by default).

### Encrypt:

```php
final readonly class ExampleService
{
    public function __construct(
        private \DBublik\Cryptography\Encrypter $encrypter,
    ) {}

    public function save(#[\SensitiveParameter] string $sensitiveValue): void
    {
        $encryptedValue = $this->encrypter->encrypt($sensitiveValue);

        // Don't forget to save $encryptedValue somewhere
    }
}
```

### Decrypt:

```php
final readonly class ExampleService
{
    public function __construct(
        private \DBublik\Cryptography\Encrypter $encrypter,
    ) {}

    public function doSomething(string $encryptedValue): mixed
    {
        $sensitiveValue = $this->encrypter->decrypt($encryptedValue);

        // Be careful! Do not show $sensitiveValue to anyone
    }
}
```

## Supported PHP versions

PHP 8.2 and later.
