<?php

declare(strict_types=1);

namespace KDuma\SDM\KeyDerivation;

use KDuma\SDM\Cipher\AESCipher;

/**
 * Key derivation for NTAG 424 DNA bulk mode operations
 *
 * Implements key diversification to derive unique keys for each tag from a master key.
 * This allows bulk tag provisioning where each tag has unique encryption keys.
 *
 * Based on the NXP AN12196 specification
 */
class KeyDerivation
{
    // Diversification constants
    private const DIV_CONST1 = "\x50\x49\x43\x43\x44\x61\x74\x61\x4b\x65\x79"; // "PICCDataKey"
    private const DIV_CONST2 = "\x53\x6c\x6f\x74\x4d\x61\x73\x74\x65\x72\x4b\x65\x79"; // "SlotMasterKey"
    private const DIV_CONST3 = "\x44\x69\x76\x42\x61\x73\x65\x4b\x65\x79"; // "DivBaseKey"

    private AESCipher $cipher;

    public function __construct(
        private readonly string $masterKey
    ) {
        $this->cipher = new AESCipher();
    }

    /**
     * Derive an undiversified key from master key
     * Used for metadata read keys in bulk mode
     *
     * @param int $keyNumber Key number (must be 1)
     * @return string Derived key (16 bytes)
     * @throws \RuntimeException If key number is not 1
     */
    public function deriveUndiversifiedKey(int $keyNumber): string
    {
        if ($keyNumber !== 1) {
            throw new \RuntimeException('Only key #1 can be derived in undiversified mode.');
        }

        // If master key is all zeros (16 or 32 bytes), return all zeros (16 bytes)
        $keyLength = strlen($this->masterKey);
        if ($this->masterKey === str_repeat("\x00", $keyLength)) {
            return str_repeat("\x00", 16);
        }

        // Return HMAC-SHA256(master_key, DIV_CONST1)[0:16]
        return $this->hmacSha256($this->masterKey, self::DIV_CONST1);
    }

    /**
     * Derive a tag-specific key from master key and UID
     * Used for file read keys in bulk mode
     *
     * @param string $uid Tag UID (7 bytes)
     * @param int $keyNumber Key number (typically 1 or 2)
     * @return string Derived key (16 bytes)
     */
    public function deriveTagKey(string $uid, int $keyNumber): string
    {
        // If master key is all zeros (16 or 32 bytes), return all zeros (16 bytes)
        $keyLength = strlen($this->masterKey);
        if ($this->masterKey === str_repeat("\x00", $keyLength)) {
            return str_repeat("\x00", 16);
        }

        // Step 1: intermediate1 = HMAC-SHA256(master_key, DIV_CONST2 + key_no)[0:16]
        $intermediate1 = $this->hmacSha256($this->masterKey, self::DIV_CONST2 . chr($keyNumber));

        // Step 2: intermediate2 = HMAC-SHA256(master_key, DIV_CONST3) (no truncation, full 32 bytes)
        $intermediate2 = $this->hmacSha256($this->masterKey, self::DIV_CONST3, noTrunc: true);

        // Step 3: intermediate3 = HMAC-SHA256(intermediate2, uid)[0:16]
        $intermediate3 = $this->hmacSha256($intermediate2, $uid);

        // Step 4: result = AES-CMAC(key=intermediate1, data=0x01 + intermediate3)
        $cmacData = "\x01" . $intermediate3;
        return $this->cipher->cmac($cmacData, $intermediate1);
    }

    /**
     * Get the master key
     *
     * @return string Master key
     */
    public function getMasterKey(): string
    {
        return $this->masterKey;
    }

    /**
     * HMAC-SHA256 with optional truncation
     *
     * @param string $key HMAC key
     * @param string $message Message to MAC
     * @param bool $noTrunc If true, return full 32-byte hash; otherwise return first 16 bytes
     * @return string HMAC result
     */
    private function hmacSha256(string $key, string $message, bool $noTrunc = false): string
    {
        $hmac = hash_hmac('sha256', $message, $key, binary: true);

        return $noTrunc ? $hmac : substr($hmac, 0, 16);
    }
}
