<?php

declare(strict_types=1);

namespace KDuma\SDM;

use KDuma\SDM\Cipher\AESCipher;

/**
 * Key derivation functions for NTAG DNA 424 SDM
 */
class KeyDerivation
{
    // Diversification constants from NTAG 424 DNA specification
    private const DIV_CONST1 = '50494343446174614b6579'; // "PICCDataKey"
    private const DIV_CONST2 = '536c6f744d61737465724b6579'; // "SlotMasterKey"
    private const DIV_CONST3 = '446976426173654b6579'; // "DivBaseKey"

    private AESCipher $cipher;

    public function __construct()
    {
        $this->cipher = new AESCipher();
    }

    /**
     * Derive an undiversified key from a master key
     *
     * @param string $masterKey The master key (binary, 16 bytes)
     * @param int $keyNumber The key number (1 or 2)
     * @return string The derived key (binary, 16 bytes)
     */
    public function deriveUndiversifiedKey(string $masterKey, int $keyNumber): string
    {
        // Check for factory key (all zeros)
        if ($masterKey === str_repeat("\x00", 16)) {
            return str_repeat("\x00", 16);
        }

        // Only key number 1 is supported for undiversified keys
        if ($keyNumber !== 1) {
            throw new \InvalidArgumentException('Only key number 1 is supported for undiversified keys');
        }

        // Derive key using HMAC-SHA256 with DIV_CONST1
        $divConst1 = hex2bin(self::DIV_CONST1);

        if ($divConst1 === false) {
            throw new \RuntimeException('Failed to decode DIV_CONST1');
        }

        // HMAC-SHA256 and truncate to 16 bytes
        $hmac = hash_hmac('sha256', $divConst1, $masterKey, true);

        return substr($hmac, 0, 16);
    }

    /**
     * Derive a tag-specific (UID-diversified) key from a master key
     *
     * @param string $masterKey The master key (binary, 16 bytes)
     * @param string $uid The UID of the tag (binary, 7 bytes)
     * @param int $keyNumber The key number (1 or 2)
     * @return string The derived key (binary, 16 bytes)
     */
    public function deriveTagKey(string $masterKey, string $uid, int $keyNumber): string
    {
        // Check for factory key (all zeros)
        if ($masterKey === str_repeat("\x00", 16)) {
            return str_repeat("\x00", 16);
        }

        // Step 1: Derive CMAC key using HMAC-SHA256 with DIV_CONST2 + key_no
        $divConst2 = hex2bin(self::DIV_CONST2);

        if ($divConst2 === false) {
            throw new \RuntimeException('Failed to decode DIV_CONST2');
        }

        $cmacKey = hash_hmac('sha256', $divConst2 . chr($keyNumber), $masterKey, true);
        $cmacKey = substr($cmacKey, 0, 16);

        // Step 2: Nested HMAC operations for UID diversification
        $divConst3 = hex2bin(self::DIV_CONST3);

        if ($divConst3 === false) {
            throw new \RuntimeException('Failed to decode DIV_CONST3');
        }

        // HMAC-SHA256(master_key, DIV_CONST3) - full 32 bytes, not truncated
        $hmac2 = hash_hmac('sha256', $divConst3, $masterKey, true);

        // HMAC-SHA256(hmac2, uid) - truncated to 16 bytes
        $hmac3 = hash_hmac('sha256', $uid, $hmac2, true);
        $hmac3 = substr($hmac3, 0, 16);

        // Step 3: CMAC with 0x01 + hmac3 as data
        $cmacInput = "\x01" . $hmac3;
        $diversifiedKey = $this->cipher->cmac($cmacInput, $cmacKey);

        return $diversifiedKey;
    }
}
