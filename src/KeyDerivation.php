<?php

declare(strict_types=1);

namespace KDuma\SDM;

use KDuma\SDM\Cipher\AESCipher;

/**
 * Key derivation functions for NTAG 424 DNA Secure Dynamic Messaging (SDM).
 *
 * This class implements the NIST SP 800-108 key derivation functions used by
 * NTAG 424 DNA NFC tags for deriving session keys from master keys. The derivation
 * process uses HMAC-SHA256 and AES-CMAC as specified in NXP Application Note AN12196.
 *
 * ## Key Derivation Methods
 *
 * The class provides two types of key derivation:
 *
 * 1. **Undiversified Keys**: Derived only from the master key, used when UID
 *    diversification is not required. Only key number 1 is supported.
 *
 * 2. **UID-Diversified Keys**: Derived from both the master key and the tag's
 *    unique identifier (UID). This ensures each tag has unique session keys,
 *    preventing key reuse across different tags even with the same master key.
 *
 * ## UID Diversification
 *
 * UID diversification binds derived keys to a specific tag's hardware UID (7 bytes).
 * This provides additional security by ensuring that:
 * - Each tag produces different session keys from the same master key
 * - Keys cannot be transferred between tags
 * - Compromising one tag's keys doesn't affect other tags
 *
 * ## Usage Example
 *
 * ```php
 * use KDuma\SDM\KeyDerivation;
 *
 * $kdf = new KeyDerivation();
 *
 * // Derive an undiversified key (key number 1 only)
 * $masterKey = hex2bin('C9EB67DF090AFF47C3B19A2516680B9D');
 * $sessionKey = $kdf->deriveUndiversifiedKey($masterKey, 1);
 *
 * // Derive a UID-diversified key for a specific tag
 * $uid = hex2bin('04E12AB3CD5E80'); // Tag's 7-byte UID
 * $tagKey = $kdf->deriveTagKey($masterKey, $uid, 1);
 * ```
 *
 * ## Specification References
 *
 * - NXP AN12196: "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints"
 * - NIST SP 800-108: "Recommendation for Key Derivation Using Pseudorandom Functions"
 * - NIST SP 800-38B: "Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication"
 *
 * @see https://www.nxp.com/docs/en/application-note/AN12196.pdf NXP AN12196
 * @see https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final NIST SP 800-108
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
     * Derive an undiversified key from a master key.
     *
     * @param string $masterKey The master key (binary, 16-32 bytes)
     * @param int    $keyNumber The key number (must be 1)
     *
     * @return string The derived key (binary, 16 bytes)
     */
    public function deriveUndiversifiedKey(string $masterKey, int $keyNumber): string
    {
        // IMPORTANT: Validate parameters BEFORE factory key check to ensure
        // invalid inputs are rejected even when using factory keys

        // Validate key number
        if (1 !== $keyNumber) {
            throw new \InvalidArgumentException('Only key number 1 is supported for undiversified keys');
        }

        // Validate master key length: 16 bytes (AES-128) to 32 bytes (AES-256)
        $keyLength = strlen($masterKey);
        if ($keyLength < 16 || $keyLength > 32) {
            throw new \InvalidArgumentException(
                sprintf('Master key must be 16-32 bytes (got %d bytes). Keys shorter than 16 bytes are cryptographically weak.', $keyLength),
            );
        }

        // Check for factory key (all zeros) - exactly 16 bytes of zeros
        if ($masterKey === str_repeat("\x00", 16)) {
            return str_repeat("\x00", 16);
        }

        // Derive key using HMAC-SHA256 with DIV_CONST1
        $divConst1 = hex2bin(self::DIV_CONST1);

        if (false === $divConst1) {
            throw new \RuntimeException('Failed to decode DIV_CONST1');
        }

        // HMAC-SHA256 and truncate to 16 bytes
        $hmac = hash_hmac('sha256', $divConst1, $masterKey, true);

        return substr($hmac, 0, 16);
    }

    /**
     * Derive a tag-specific (UID-diversified) key from a master key.
     *
     * @param string $masterKey The master key (binary, 16-32 bytes)
     * @param string $uid       The UID of the tag (binary, 7 bytes)
     * @param int    $keyNumber The key number (1 or 2)
     *
     * @return string The derived key (binary, 16 bytes)
     */
    public function deriveTagKey(string $masterKey, string $uid, int $keyNumber): string
    {
        // IMPORTANT: Validate parameters BEFORE factory key check to ensure
        // invalid inputs are rejected even when using factory keys

        // Validate UID length
        if (7 !== strlen($uid)) {
            throw new \InvalidArgumentException(sprintf('UID must be exactly 7 bytes, got %d bytes', strlen($uid)));
        }

        // Validate key number
        if (1 !== $keyNumber && 2 !== $keyNumber) {
            throw new \InvalidArgumentException(sprintf('Key number must be 1 or 2, got %d', $keyNumber));
        }

        // Validate master key length: 16 bytes (AES-128) to 32 bytes (AES-256)
        $keyLength = strlen($masterKey);
        if ($keyLength < 16 || $keyLength > 32) {
            throw new \InvalidArgumentException(
                sprintf('Master key must be 16-32 bytes (got %d bytes). Keys shorter than 16 bytes are cryptographically weak.', $keyLength),
            );
        }

        // Check for factory key (all zeros) - exactly 16 bytes of zeros
        if ($masterKey === str_repeat("\x00", 16)) {
            return str_repeat("\x00", 16);
        }

        // Step 1: Derive CMAC key using HMAC-SHA256 with DIV_CONST2 + key_no
        $divConst2 = hex2bin(self::DIV_CONST2);

        if (false === $divConst2) {
            throw new \RuntimeException('Failed to decode DIV_CONST2');
        }

        $cmacKey = hash_hmac('sha256', $divConst2.chr($keyNumber), $masterKey, true);
        $cmacKey = substr($cmacKey, 0, 16);

        // Step 2: Nested HMAC operations for UID diversification
        $divConst3 = hex2bin(self::DIV_CONST3);

        if (false === $divConst3) {
            throw new \RuntimeException('Failed to decode DIV_CONST3');
        }

        // HMAC-SHA256(master_key, DIV_CONST3) - full 32 bytes, not truncated
        $hmac2 = hash_hmac('sha256', $divConst3, $masterKey, true);

        // HMAC-SHA256(hmac2, uid) - truncated to 16 bytes
        $hmac3 = hash_hmac('sha256', $uid, $hmac2, true);
        $hmac3 = substr($hmac3, 0, 16);

        // Step 3: CMAC with 0x01 + hmac3 as data
        $cmacInput = "\x01".$hmac3;

        return $this->cipher->cmac($cmacInput, $cmacKey);
    }
}
