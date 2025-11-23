<?php

declare(strict_types=1);

namespace KDuma\SDM;

use KDuma\SDM\Cipher\AESCipher;
use KDuma\SDM\Cipher\LRPCipher;
use KDuma\SDM\Exceptions\DecryptionException;
use KDuma\SDM\Exceptions\ValidationException;

/**
 * Main class for NTAG DNA 424 Secure Dynamic Messaging operations.
 *
 * This implementation is based on the examples provided in:
 * - AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
 *
 * @see https://www.nxp.com/docs/en/application-note/AN12196.pdf
 */
class SDM implements SDMInterface
{
    /**
     * Session Vector 2 prefix for CMAC session key derivation.
     *
     * Used in calculateSdmmac() for deriving the CMAC session key.
     * Format: 0x3C 0xC3 0x00 0x01 0x00 0x80 || PICCData
     *
     * @see AN12196 Section 5.3.2 - CMAC Calculation
     */
    private const SV2_PREFIX_CMAC = "\x3C\xC3\x00\x01\x00\x80";

    /**
     * Session Vector 1 prefix for encryption session key derivation.
     *
     * Used in decryptFileData() for deriving the encryption session key.
     * Format: 0xC3 0x3C 0x00 0x01 0x00 0x80 || PICCData
     *
     * @see AN12196 Section 5.3.1 - SDMENCFileData Encryption
     */
    private const SV1_PREFIX_ENC = "\xC3\x3C\x00\x01\x00\x80";

    /**
     * LRP protocol version identifier.
     *
     * Used as a prefix in LRP session vector construction for both SV1 and SV2.
     * This 4-byte sequence identifies the protocol version in LRP mode operations.
     *
     * @see AN12304 Section 3 - Leakage Resilient Primitive (LRP)
     */
    private const LRP_PROTOCOL_PREFIX = "\x00\x01\x00\x80";

    /**
     * LRP stream terminator.
     *
     * 2-byte trailer appended to padded LRP session vectors before CMAC calculation.
     * This terminator is added after padding the session vector to a multiple of
     * the block size (16 bytes).
     *
     * @see AN12304 Section 3 - Leakage Resilient Primitive (LRP)
     */
    private const LRP_STREAM_TRAILER = "\x1E\xE1";

    /**
     * PICCDataTag bit mask for UID mirroring enabled flag.
     *
     * Bit 7 of PICCDataTag byte indicates if UID is included in the encrypted data.
     *
     * @see AN12196 Section 5.2 - PICCDataTag Structure
     */
    private const PICC_UID_MIRROR_MASK = 0x80;

    /**
     * PICCDataTag bit mask for SDMReadCtr enabled flag.
     *
     * Bit 6 of PICCDataTag byte indicates if read counter is included in the encrypted data.
     *
     * @see AN12196 Section 5.2 - PICCDataTag Structure
     */
    private const PICC_READ_CTR_MASK = 0x40;

    /**
     * PICCDataTag bit mask for UID length.
     *
     * Bits 0-3 of PICCDataTag byte contain the UID length.
     *
     * @see AN12196 Section 5.2 - PICCDataTag Structure
     */
    private const PICC_UID_LENGTH_MASK = 0x0F;

    /**
     * Expected UID length for NTAG 424 DNA.
     *
     * NTAG 424 DNA uses 7-byte UIDs (single size).
     *
     * @see AN12196 Section 3.1 - UID
     */
    private const PICC_SUPPORTED_UID_LENGTH = 0x07;

    private AESCipher $cipher;

    public function __construct(
        private readonly string $encKey,
        private readonly string $macKey,
        private readonly string $sdmmacParam = '',
    ) {
        $this->cipher = new AESCipher();
    }

    public function decrypt(string $encData, string $encFileData, string $cmac): array
    {
        return $this->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: $this->encKey,
            sdmFileReadKey: fn (string $uid) => $this->macKey,
            piccEncData: $encData,
            sdmmac: $cmac,
            encFileData: $encFileData,
        );
    }

    /**
     * Validate plain SUN message authentication (convenience wrapper).
     *
     * This method validates a plain (unencrypted) SUN message by checking its SDMMAC.
     * The data must be in the format: [ UID (7 bytes) ][ SDMReadCtr (3 bytes) ]
     *
     * Note: This method assumes AES encryption mode. For LRP mode support or more
     * control over validation parameters, use validatePlainSun() directly.
     *
     * @param string $data The plain SUN data: UID (7 bytes) + ReadCtr (3 bytes)
     * @param string $cmac The SDMMAC to validate against (8 bytes)
     *
     * @return bool True if the SDMMAC is valid, false otherwise
     *
     * @see validatePlainSun() for more detailed validation with mode selection
     */
    public function validate(string $data, string $cmac): bool
    {
        // Validate data length: must be exactly 10 bytes (7-byte UID + 3-byte ReadCtr)
        // Return false instead of throwing to maintain backwards compatibility
        if (10 !== strlen($data)) {
            return false;
        }

        // Validate CMAC length: must be exactly 8 bytes
        // Return false instead of throwing to maintain backwards compatibility
        if (8 !== strlen($cmac)) {
            return false;
        }

        try {
            $this->validatePlainSun(
                uid: substr($data, 0, 7),
                readCtr: substr($data, 7, 3),
                sdmmac: $cmac,
                sdmFileReadKey: $this->macKey,
                mode: EncMode::AES,
            );

            return true;
        } catch (ValidationException) {
            return false;
        }
    }

    /**
     * Calculate SDMMAC for NTAG 424 DNA.
     *
     * @param ParamMode    $paramMode      Type of dynamic URL encoding
     * @param string       $sdmFileReadKey MAC calculation key (K_SDMFileReadKey)
     * @param string       $piccData       [ UID ][ SDMReadCtr ]
     * @param null|string  $encFileData    SDMEncFileData (if used)
     * @param null|EncMode $mode           Encryption mode used by PICC - EncMode::AES (default) or EncMode::LRP
     *
     * @return string calculated SDMMAC (8 bytes)
     */
    public function calculateSdmmac(
        ParamMode $paramMode,
        string $sdmFileReadKey,
        string $piccData,
        ?string $encFileData = null,
        ?EncMode $mode = null,
    ): string {
        if (null === $mode) {
            $mode = EncMode::AES;
        }

        $inputBuf = '';

        if (null !== $encFileData) {
            $sdmmacParamText = '&'.$this->sdmmacParam.'=';

            if (ParamMode::BULK === $paramMode || '' === $this->sdmmacParam) {
                $sdmmacParamText = '';
            }

            $inputBuf .= strtoupper(bin2hex($encFileData)).$sdmmacParamText;
        }

        if (EncMode::LRP === $mode) {
            // LRP mode - derive CMAC session key using SV2 with different format
            $sv2stream = self::LRP_PROTOCOL_PREFIX.$piccData;

            // Pad until (length + 2) is a multiple of block size, then add 2-byte trailer
            while ((strlen($sv2stream) + 2) % 16 !== 0) {
                $sv2stream .= "\x00";
            }
            $sv2stream .= self::LRP_STREAM_TRAILER;

            // Derive master key using LRP CMAC
            $lrpCipher = new LRPCipher($sdmFileReadKey, 0);
            $masterKey = $lrpCipher->cmac($sv2stream, $sdmFileReadKey);

            // Calculate CMAC with session key (update_mode=0 for session macing)
            $lrpSession = new LRPCipher($masterKey, 0);
            $macDigest = $lrpSession->cmac($inputBuf, $masterKey);

            // Extract odd bytes (1, 3, 5, 7, 9, 11, 13, 15) to form 8-byte SDMMAC
            // Note: This reduces MAC strength from 128 bits to 64 bits as specified
            // by the NTAG 424 DNA protocol. The odd-byte extraction is part of the
            // AN12196 specification for SUN message authentication.
            $result = '';
            for ($i = 1; $i < 16; $i += 2) {
                $result .= $macDigest[$i];
            }

            return $result;
        }

        // AES mode - derive CMAC session key using SV2
        $sv2stream = self::SV2_PREFIX_CMAC.$piccData;

        // Zero padding to next 16-byte block boundary
        $paddedLength = (int) (ceil(strlen($sv2stream) / 16) * 16);
        $sv2stream = str_pad($sv2stream, $paddedLength, "\x00");

        $c2 = $this->cipher->cmac($sv2stream, $sdmFileReadKey);
        $macDigest = $this->cipher->cmac($inputBuf, $c2);

        // Extract odd bytes (1, 3, 5, 7, 9, 11, 13, 15) to form 8-byte SDMMAC
        // Note: This reduces MAC strength from 128 bits to 64 bits as specified
        // by the NTAG 424 DNA protocol. The odd-byte extraction is part of the
        // AN12196 specification for SUN message authentication.
        $result = '';
        for ($i = 1; $i < 16; $i += 2) {
            $result .= $macDigest[$i];
        }

        return $result;
    }

    /**
     * Decrypt SDMEncFileData for NTAG 424 DNA.
     *
     * @param string       $sdmFileReadKey SUN decryption key (K_SDMFileReadKey)
     * @param string       $piccData       PICCDataTag [ || UID ][ || SDMReadCtr ]]
     * @param string       $readCtr        SDMReadCtr
     * @param string       $encFileData    SDMEncFileData
     * @param null|EncMode $mode           Encryption mode used by PICC - EncMode::AES (default) or EncMode::LRP
     *
     * @return string decrypted file data (bytes)
     */
    public function decryptFileData(
        string $sdmFileReadKey,
        string $piccData,
        string $readCtr,
        string $encFileData,
        ?EncMode $mode = null,
    ): string {
        if (null === $mode) {
            $mode = EncMode::AES;
        }

        if (EncMode::LRP === $mode) {
            // LRP mode - derive encryption session key using SV1 with different format
            $sv1stream = self::LRP_PROTOCOL_PREFIX.$piccData;

            // Pad until (length + 2) is a multiple of block size, then add 2-byte trailer
            while ((strlen($sv1stream) + 2) % 16 !== 0) {
                $sv1stream .= "\x00";
            }
            $sv1stream .= self::LRP_STREAM_TRAILER;

            // Derive master key using LRP CMAC
            $lrpCipher = new LRPCipher($sdmFileReadKey, 0);
            $masterKey = $lrpCipher->cmac($sv1stream, $sdmFileReadKey);

            // Decrypt file data using LRP with mode 1 and read counter + 3 zero bytes as IV
            $lrpSession = new LRPCipher($masterKey, 1, $readCtr."\x00\x00\x00", false);

            return $lrpSession->decrypt($encFileData, $masterKey, $readCtr."\x00\x00\x00");
        }

        // AES mode - derive encryption session key using SV1
        $sv1stream = self::SV1_PREFIX_ENC.$piccData;

        // Zero padding to next 16-byte block boundary
        $paddedLength = (int) (ceil(strlen($sv1stream) / 16) * 16);
        $sv1stream = str_pad($sv1stream, $paddedLength, "\x00");

        $kSesSDMFileReadEnc = $this->cipher->cmac($sv1stream, $sdmFileReadKey);
        $ive = $this->cipher->encryptECB($readCtr.str_repeat("\x00", 13), $kSesSDMFileReadEnc);

        return $this->cipher->decrypt($encFileData, $kSesSDMFileReadEnc, $ive);
    }

    /**
     * Validate the SDMMAC of plain (unencrypted) UID and read counter data.
     *
     * This method verifies that the provided SDMMAC correctly authenticates
     * the given UID and read counter values. It does not decrypt any data,
     * only validates the MAC.
     *
     * @param string       $uid            The tag's unique identifier (7 bytes)
     * @param string       $readCtr        The SDM read counter value (3 bytes, little-endian)
     * @param string       $sdmmac         The SDMMAC to validate against (8 bytes)
     * @param string       $sdmFileReadKey The MAC calculation key (K_SDMFileReadKey, 16 bytes)
     * @param null|EncMode $mode           Encryption mode used (EncMode::AES or EncMode::LRP)
     *
     * @return array{encryption_mode: EncMode, uid: string, read_ctr: int}
     *
     * @throws ValidationException if MAC is invalid or input data is malformed
     */
    public function validatePlainSun(
        string $uid,
        string $readCtr,
        string $sdmmac,
        string $sdmFileReadKey,
        ?EncMode $mode = null,
    ): array {
        // Validate UID length
        if (7 !== strlen($uid)) {
            throw new ValidationException('Invalid UID length - expected 7 bytes, got '.strlen($uid).' bytes. This may indicate malformed or truncated input data.');
        }

        // Validate read counter length
        if (3 !== strlen($readCtr)) {
            throw new ValidationException('Invalid read counter length - expected 3 bytes, got '.strlen($readCtr).' bytes. This may indicate malformed or truncated input data.');
        }

        // Validate SDMMAC length
        if (8 !== strlen($sdmmac)) {
            throw new ValidationException('Invalid SDMMAC length - expected 8 bytes, got '.strlen($sdmmac).' bytes. This may indicate malformed or truncated input data.');
        }

        if (null === $mode) {
            $mode = EncMode::AES;
        }

        // Reverse the read counter bytes for little-endian to big-endian conversion
        $readCtrReversed = strrev($readCtr);

        $dataStream = $uid.$readCtrReversed;

        $properSdmmac = $this->calculateSdmmac(
            ParamMode::SEPARATED,
            $sdmFileReadKey,
            $dataStream,
            mode: $mode,
        );

        if (!\hash_equals($sdmmac, $properSdmmac)) {
            throw new ValidationException('Message is not properly signed - invalid MAC');
        }

        // Convert 3-byte read counter to integer (big-endian)
        // Safe on both 32-bit and 64-bit: max value is 0xFFFFFF = 16,777,215
        $unpacked = unpack('N', "\x00".$readCtr);
        if (false === $unpacked) {
            throw new ValidationException('Failed to unpack read counter');
        }
        $readCtrNum = $unpacked[1];

        return [
            'encryption_mode' => $mode,
            'uid' => $uid,
            'read_ctr' => $readCtrNum,
        ];
    }

    /**
     * Get encryption mode from PICC encrypted data length.
     *
     * @param string $piccEncData Encrypted PICC data
     *
     * @return EncMode Detected encryption mode
     *
     * @throws DecryptionException if unsupported encryption mode
     */
    public function getEncryptionMode(string $piccEncData): EncMode
    {
        $length = strlen($piccEncData);

        if (16 === $length) {
            return EncMode::AES;
        }

        if (24 === $length) {
            return EncMode::LRP;
        }

        throw new DecryptionException('Invalid encrypted PICC data length - expected 16 bytes (AES) or 24 bytes (LRP), got '.$length.' bytes. This may indicate malformed or truncated input data.');
    }

    /**
     * Decrypt SUN message for NTAG 424 DNA.
     *
     * @param ParamMode   $paramMode      Type of dynamic URL encoding
     * @param string      $sdmMetaReadKey SUN decryption key (K_SDMMetaReadKey)
     * @param callable    $sdmFileReadKey MAC calculation key function (K_SDMFileReadKey)
     * @param string      $piccEncData    Encrypted PICC data
     * @param string      $sdmmac         SDMMAC of the SUN message
     * @param null|string $encFileData    SDMEncFileData (if present)
     *
     * @return array{picc_data_tag: string, uid: string, read_ctr: int, file_data: null|string, encryption_mode: EncMode}
     *
     * @throws DecryptionException if SUN message is invalid
     * @throws ValidationException if MAC is invalid
     */
    public function decryptSunMessage(
        ParamMode $paramMode,
        string $sdmMetaReadKey,
        callable $sdmFileReadKey,
        string $piccEncData,
        string $sdmmac,
        ?string $encFileData = null,
    ): array {
        // Validate SDMMAC length (must be exactly 8 bytes)
        if (8 !== strlen($sdmmac)) {
            throw new DecryptionException('Invalid SDMMAC length - expected 8 bytes, got '.strlen($sdmmac).' bytes. This may indicate malformed or truncated input data.');
        }

        // Validate encrypted file data if present (must be multiple of 16 bytes for AES)
        if (null !== $encFileData && 0 !== strlen($encFileData) % 16) {
            throw new DecryptionException('Invalid encrypted file data length - must be a multiple of 16 bytes, got '.strlen($encFileData).' bytes. This may indicate malformed or truncated input data.');
        }

        $mode = $this->getEncryptionMode($piccEncData);

        if (EncMode::LRP === $mode) {
            // LRP mode - extract PICC random and decrypt using LRP
            $piccRandom = substr($piccEncData, 0, 8);
            $encryptedPiccData = substr($piccEncData, 8);

            // Use LRP to decrypt PICC data (no padding for PICC data, use 8-byte PICC random as counter)
            $lrpCipher = new LRPCipher($sdmMetaReadKey, 0, $piccRandom, false);
            $plaintext = $lrpCipher->decrypt($encryptedPiccData, $sdmMetaReadKey, $piccRandom);
        } else {
            // AES mode - decrypt using CBC with zero IV
            $plaintext = $this->cipher->decrypt($piccEncData, $sdmMetaReadKey, str_repeat("\x00", 16));
        }

        // Parse PICCDataTag byte to extract configuration flags and UID length
        $piccDataTag = $plaintext[0];
        $uidMirroringEn = (ord($piccDataTag) & self::PICC_UID_MIRROR_MASK) === self::PICC_UID_MIRROR_MASK;
        $sdmReadCtrEn = (ord($piccDataTag) & self::PICC_READ_CTR_MASK) === self::PICC_READ_CTR_MASK;
        $uidLength = ord($piccDataTag) & self::PICC_UID_LENGTH_MASK;

        $uid = null;
        $readCtr = null;
        $readCtrNum = null;
        $fileData = null;
        $dataStream = '';
        $offset = 1;

        // Track UID length validation error without throwing immediately (timing attack mitigation)
        // Other errors are thrown immediately as they don't reveal cryptographic information
        $uidLengthError = false;

        // Validate UID length - only 7-byte UIDs are supported by NTAG 424 DNA
        // Continue execution with fake data to maintain constant timing
        if (self::PICC_SUPPORTED_UID_LENGTH !== $uidLength) {
            $uidLengthError = true;
            // Use fake UID for remaining operations
            $uid = str_repeat("\x00", 7);
            $dataStream = str_repeat("\x00", 10);
        } else {
            // Valid UID length - extract real data
            if ($uidMirroringEn) {
                $uid = substr($plaintext, $offset, $uidLength);
                $dataStream .= $uid;
                $offset += $uidLength;
            }

            if ($sdmReadCtrEn) {
                $readCtr = substr($plaintext, $offset, 3);
                $dataStream .= $readCtr;
                // Convert 3-byte read counter to integer (little-endian)
                // Safe on both 32-bit and 64-bit: max value is 0xFFFFFF = 16,777,215
                $unpacked = unpack('V', $readCtr."\x00");
                if (false === $unpacked) {
                    throw new DecryptionException('Failed to unpack read counter');
                }
                $readCtrNum = $unpacked[1];
            }

            if (null === $uid) {
                throw new DecryptionException('UID cannot be null');
            }
        }

        // Always perform MAC calculation (real or fake) for constant timing
        $fileKey = $sdmFileReadKey($uid);
        $calculatedMac = $this->calculateSdmmac($paramMode, $fileKey, $dataStream, $encFileData, $mode);

        // Throw UID length error after MAC calculation (timing attack mitigation)
        if ($uidLengthError) {
            throw new DecryptionException('Failed to decrypt PICCData - invalid encryption key or malformed data');
        }

        // Verify MAC using constant-time comparison
        if (!\hash_equals($sdmmac, $calculatedMac)) {
            throw new ValidationException('Message is not properly signed - invalid MAC');
        }

        // Decrypt file data if present
        if (null !== $encFileData) {
            if (null === $readCtr) {
                throw new DecryptionException('SDMReadCtr is required to decipher SDMENCFileData');
            }

            $fileData = $this->decryptFileData($fileKey, $dataStream, $readCtr, $encFileData, $mode);
        }

        return [
            'picc_data_tag' => $piccDataTag,
            'uid' => $uid,
            'read_ctr' => $readCtrNum,
            'file_data' => $fileData,
            'encryption_mode' => $mode,
        ];
    }
}
