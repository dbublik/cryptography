<?php

declare(strict_types=1);

namespace DBublik\Cryptography;

enum Algorithm: string
{
    case Aes128Gcm = 'aes-128-gcm';
    case Aes192Gcm = 'aes-192-gcm';
    case Aes256Gcm = 'aes-256-gcm';
}
