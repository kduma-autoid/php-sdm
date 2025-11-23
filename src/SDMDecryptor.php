<?php

declare(strict_types=1);

namespace KDuma\SDM;

use KDuma\SDM\Cipher\AESCipher;
use KDuma\SDM\Cipher\CipherInterface;
use KDuma\SDM\Cipher\LRPCipher;
use KDuma\SDM\Enums\EncryptionMode;
use KDuma\SDM\Enums\ParameterMode;
use KDuma\SDM\Exceptions\ValidationException;
use KDuma\SDM\KeyDerivation\KeyDerivation;

/**
 * SDM Message Decryptor for NTAG 424 DNA
 *
 * Handles decryption and validation of Secure Dynamic Messaging (SDM) messages
 * from NTAG 424 DNA tags, supporting both AES and LRP encryption modes.
 */
class SDMDecryptor
{
    private CipherInterface $aesCipher;
    private CipherInterface $lrpCipher;

    public function __construct(
        private readonly ParameterMode $parameterMode,
        private readonly ?string $sdmMetaReadKey = null,
        private readonly ?string $sdmFileReadKey = null,
        private readonly ?KeyDerivation $sdmFileReadKeyDerivation = null,
        private readonly ?int $sdmFileReadKeyNumber = null,
        private readonly ?string $sdmmacParam = 'cmac',
    ) {
        $this->aesCipher = new AESCipher();
        $this->lrpCipher = new LRPCipher();
    }

    /**
     * Decrypt an SDM message
     *
     * @param string $piccEncData Encrypted PICC data (containing UID and read counter)
     * @param string $sdmmac SDMMAC for message authentication
     * @param string|null $encFileData Optional encrypted file data
     * @return DecryptionResult Decrypted message data
     * @throws ValidationException If SDMMAC validation fails
     */
    public function decrypt(
        string $piccEncData,
        string $sdmmac,
        ?string $encFileData = null
    ): DecryptionResult {
        // Detect encryption mode based on PICC data length
        $encryptionMode = $this->detectEncryptionMode($piccEncData);
        $cipher = $encryptionMode === EncryptionMode::AES ? $this->aesCipher : $this->lrpCipher;

        // Decrypt PICC data to get UID and read counter
        $piccData = $this->decryptPICCData($piccEncData, $cipher, $encryptionMode);

        // Get the appropriate file read key
        $fileReadKey = $this->getFileReadKey($piccData['uid']);

        // Validate SDMMAC (uses file read key)
        $this->validateSDMMAC($piccData['uid'], $piccData['read_counter_bytes'], $encFileData, $sdmmac, $cipher, $fileReadKey);

        // Decrypt file data if present
        $fileData = null;
        if ($encFileData !== null && $fileReadKey !== null) {
            $fileData = $this->decryptFileData($encFileData, $fileReadKey, $piccData['uid'], $piccData['read_counter_bytes'], $cipher);
        }

        return new DecryptionResult(
            piccDataTag: $piccData['picc_data_tag'],
            uid: $piccData['uid'],
            readCounter: $piccData['read_counter'],
            fileData: $fileData,
            encryptionMode: $encryptionMode
        );
    }

    /**
     * Validate a plain SUN message (no encryption, only MAC)
     *
     * @param string $uid Tag UID
     * @param string $readCounter Read counter (3 bytes, big-endian)
     * @param string $sdmmac SDMMAC for validation
     * @param EncryptionMode $encryptionMode Encryption mode (AES or LRP)
     * @return bool True if validation succeeds
     * @throws ValidationException If validation fails
     */
    public function validatePlainSUN(
        string $uid,
        string $readCounter,
        string $sdmmac,
        EncryptionMode $encryptionMode
    ): bool {
        $cipher = $encryptionMode === EncryptionMode::AES ? $this->aesCipher : $this->lrpCipher;

        // For plain SUN, the read counter comes as big-endian and needs to be reversed
        // to little-endian for SDMMAC calculation
        $readCounterReversed = strrev($readCounter);

        // For plain SUN, use the meta read key (which is the file read key in this context)
        $this->validateSDMMAC($uid, $readCounterReversed, null, $sdmmac, $cipher, $this->sdmMetaReadKey);

        return true;
    }

    /**
     * Detect encryption mode based on encrypted PICC data length
     *
     * @param string $piccEncData Encrypted PICC data
     * @return EncryptionMode Detected encryption mode
     */
    private function detectEncryptionMode(string $piccEncData): EncryptionMode
    {
        // AES mode: 16 bytes for basic PICC data
        // LRP mode: 24 bytes for basic PICC data
        $length = strlen($piccEncData);

        if ($length === 16) {
            return EncryptionMode::AES;
        } elseif ($length === 24) {
            return EncryptionMode::LRP;
        }

        // Default to AES for other lengths (may need adjustment)
        return EncryptionMode::AES;
    }

    /**
     * Decrypt PICC data to extract UID and read counter
     *
     * @param string $piccEncData Encrypted PICC data
     * @param CipherInterface $cipher Cipher to use for decryption
     * @param EncryptionMode $encryptionMode Encryption mode
     * @return array{picc_data_tag: string, uid: string, read_counter: int, read_counter_bytes: string}
     */
    private function decryptPICCData(string $piccEncData, CipherInterface $cipher, EncryptionMode $encryptionMode): array
    {
        if ($this->sdmMetaReadKey === null) {
            throw new \InvalidArgumentException('SDM meta read key is required for decryption');
        }

        // Decrypt PICC data using zero IV
        $iv = str_repeat("\x00", 16);
        $decrypted = $cipher->decrypt($piccEncData, $this->sdmMetaReadKey, $iv);

        // Parse decrypted PICC data
        // Format: [PICC Data Tag (1 byte)][UID (7 bytes)][Read Counter (3 bytes)][Padding...]
        $piccDataTag = substr($decrypted, 0, 1);
        $uid = substr($decrypted, 1, 7);
        $readCounterBytes = substr($decrypted, 8, 3);

        // Convert read counter from 3-byte little-endian to integer
        // Add a zero byte at the end and unpack as 32-bit little-endian unsigned integer
        $readCounter = unpack('V', $readCounterBytes . "\x00")[1];

        return [
            'picc_data_tag' => $piccDataTag,
            'uid' => $uid,
            'read_counter' => $readCounter,
            'read_counter_bytes' => $readCounterBytes,
        ];
    }

    /**
     * Get the file read key (either static or derived)
     *
     * @param string $uid Tag UID for key derivation in bulk mode
     * @return string|null File read key
     */
    private function getFileReadKey(string $uid): ?string
    {
        if ($this->sdmFileReadKey !== null) {
            return $this->sdmFileReadKey;
        }

        if ($this->sdmFileReadKeyDerivation !== null && $this->sdmFileReadKeyNumber !== null) {
            return $this->sdmFileReadKeyDerivation->deriveTagKey($uid, $this->sdmFileReadKeyNumber);
        }

        return null;
    }

    /**
     * Validate SDMMAC
     *
     * @param string $uid Tag UID
     * @param string $readCounterBytes Read counter (3 bytes)
     * @param string|null $encFileData Encrypted file data (optional)
     * @param string $expectedSdmmac Expected SDMMAC value
     * @param CipherInterface $cipher Cipher to use for MAC calculation
     * @param string|null $fileReadKey File read key for SDMMAC calculation
     * @throws ValidationException If MAC validation fails
     */
    private function validateSDMMAC(
        string $uid,
        string $readCounterBytes,
        ?string $encFileData,
        string $expectedSdmmac,
        CipherInterface $cipher,
        ?string $fileReadKey = null
    ): void {
        // Use file read key if provided, otherwise fall back to meta read key
        $keyForMac = $fileReadKey ?? $this->sdmMetaReadKey;

        if ($keyForMac === null) {
            throw new \InvalidArgumentException('A key is required for SDMMAC validation');
        }

        $calculatedSdmmac = $this->calculateSDMMAC($uid, $readCounterBytes, $encFileData, $cipher, $keyForMac);

        // Compare MACs (constant-time comparison to prevent timing attacks)
        if (!hash_equals($calculatedSdmmac, $expectedSdmmac)) {
            throw new ValidationException('SDMMAC validation failed');
        }
    }

    /**
     * Calculate SDMMAC for NTAG 424 DNA
     *
     * Based on AN12196 specification
     *
     * @param string $uid Tag UID
     * @param string $readCounterBytes Read counter (3 bytes)
     * @param string|null $encFileData Encrypted file data (optional)
     * @param CipherInterface $cipher Cipher to use for MAC calculation
     * @param string $fileReadKey File read key for SDMMAC calculation
     * @return string Calculated SDMMAC (8 bytes)
     */
    private function calculateSDMMAC(
        string $uid,
        string $readCounterBytes,
        ?string $encFileData,
        CipherInterface $cipher,
        string $fileReadKey
    ): string {
        // Build input buffer for MAC
        // For encrypted file data, include as uppercase hex
        $inputBuf = '';
        if ($encFileData !== null) {
            $inputBuf = strtoupper(bin2hex($encFileData));
            // Add parameter separator unless in BULK mode or sdmmacParam is empty
            if ($this->parameterMode !== ParameterMode::BULK && !empty($this->sdmmacParam)) {
                $inputBuf .= '&' . $this->sdmmacParam . '=';
            }
        }

        // Build SV2 stream for session key derivation
        // SV2 = 0x3CC3 0x0001 0x0080 || UID || ReadCounter || Padding
        $sv2Stream = "\x3C\xC3\x00\x01\x00\x80" . $uid . $readCounterBytes;

        // Zero-pad to 16-byte boundary
        while (strlen($sv2Stream) % 16 !== 0) {
            $sv2Stream .= "\x00";
        }

        // First CMAC: Calculate session key
        // CMAC(sdm_file_read_key, sv2Stream)
        $sessionKey = $cipher->cmac($sv2Stream, $fileReadKey);

        // Second CMAC: Calculate MAC of input buffer using session key
        // CMAC(sessionKey, inputBuf)
        $macDigest = $cipher->cmac($inputBuf, $sessionKey);

        // Extract SDMMAC: Take odd-indexed bytes [1,3,5,7,9,11,13,15]
        $sdmmac = '';
        for ($i = 1; $i < 16; $i += 2) {
            $sdmmac .= $macDigest[$i];
        }

        return $sdmmac;
    }

    /**
     * Decrypt file data
     *
     * Based on AN12196 specification
     *
     * @param string $encFileData Encrypted file data
     * @param string $fileReadKey File read key
     * @param string $uid Tag UID
     * @param string $readCounterBytes Read counter bytes (3 bytes)
     * @param CipherInterface $cipher Cipher to use for decryption
     * @return string Decrypted file data
     */
    private function decryptFileData(
        string $encFileData,
        string $fileReadKey,
        string $uid,
        string $readCounterBytes,
        CipherInterface $cipher
    ): string {
        // Build SV1 stream for session key derivation
        // SV1 = 0xC33C 0x0001 0x0080 || UID || ReadCounter || Padding
        $sv1Stream = "\xC3\x3C\x00\x01\x00\x80" . $uid . $readCounterBytes;

        // Zero-pad to 16-byte boundary
        while (strlen($sv1Stream) % 16 !== 0) {
            $sv1Stream .= "\x00";
        }

        // Derive session encryption key using CMAC
        // k_ses_sdm_file_read_enc = CMAC(sdm_file_read_key, sv1Stream)
        $sessionEncKey = $cipher->cmac($sv1Stream, $fileReadKey);

        // Generate IV by encrypting (read_ctr + 13 zero bytes) using ECB mode
        // IV = AES_ECB(k_ses_sdm_file_read_enc, read_ctr || 0x00...00)
        $ivInput = $readCounterBytes . str_repeat("\x00", 13);
        $iv = $cipher->encrypt($ivInput, $sessionEncKey, str_repeat("\x00", 16));

        // Decrypt file data using CBC mode with session key and generated IV
        $decrypted = $cipher->decrypt($encFileData, $sessionEncKey, $iv);

        // Remove PKCS#7 padding if present
        $paddingLength = ord($decrypted[strlen($decrypted) - 1]);
        if ($paddingLength > 0 && $paddingLength <= 16) {
            // Verify padding is valid
            $isValidPadding = true;
            for ($i = 1; $i <= $paddingLength; $i++) {
                if (ord($decrypted[strlen($decrypted) - $i]) !== $paddingLength) {
                    $isValidPadding = false;
                    break;
                }
            }
            if ($isValidPadding) {
                $decrypted = substr($decrypted, 0, -$paddingLength);
            }
        }

        return $decrypted;
    }
}
