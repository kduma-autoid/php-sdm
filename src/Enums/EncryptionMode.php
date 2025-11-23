<?php

declare(strict_types=1);

namespace KDuma\SDM\Enums;

/**
 * Encryption modes supported by NTAG 424 DNA
 */
enum EncryptionMode: string
{
    case AES = 'AES';
    case LRP = 'LRP';
}
