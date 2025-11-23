<?php

declare(strict_types=1);

namespace KDuma\SDM\Exceptions;

/**
 * Thrown when decryption of SDM data fails.
 * 
 * This typically indicates:
 * - Incorrect encryption key
 * - Corrupted encrypted data
 * - Unsupported encryption algorithm or mode
 */
class DecryptionException extends SDMException
{
}
