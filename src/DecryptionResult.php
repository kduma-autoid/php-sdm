<?php

declare(strict_types=1);

namespace KDuma\SDM;

use KDuma\SDM\Enums\EncryptionMode;

/**
 * Result of SDM message decryption
 */
class DecryptionResult
{
    public function __construct(
        public readonly string $piccDataTag,
        public readonly string $uid,
        public readonly int $readCounter,
        public readonly ?string $fileData,
        public readonly EncryptionMode $encryptionMode,
    ) {
    }
}
