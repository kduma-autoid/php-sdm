<?php

declare(strict_types=1);

namespace KDuma\SDM;

use KDuma\SDM\Cipher\AESCipher;
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
            sdmFileReadKey: fn () => $this->macKey,
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
        if (10 !== strlen($data)) {
            return false;
        }

        // Validate CMAC length: must be exactly 8 bytes
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

        if (EncMode::LRP === $mode) {
            throw new \RuntimeException('LRP mode is not supported');
        }

        $inputBuf = '';

        if (null !== $encFileData) {
            $sdmmacParamText = '&'.$this->sdmmacParam.'=';

            if (ParamMode::BULK === $paramMode || '' === $this->sdmmacParam) {
                $sdmmacParamText = '';
            }

            $inputBuf .= strtoupper(bin2hex($encFileData)).$sdmmacParamText;
        }

        // AES mode - derive CMAC session key using SV2
        $sv2stream = self::SV2_PREFIX_CMAC.$piccData;

        // Zero padding to next 16-byte block boundary
        $paddedLength = (int) (ceil(strlen($sv2stream) / 16) * 16);
        $sv2stream = str_pad($sv2stream, $paddedLength, "\x00");

        $c2 = $this->cipher->cmac($sv2stream, $sdmFileReadKey);
        $macDigest = $this->cipher->cmac($inputBuf, $c2);

        // Extract odd bytes (1, 3, 5, 7, 9, 11, 13, 15)
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
            throw new \RuntimeException('LRP mode is not supported');
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
     * Validate plain SUN message.
     *
     * @param string       $uid            UID of the tag (7 bytes)
     * @param string       $readCtr        SDMReadCtr (3 bytes)
     * @param string       $sdmmac         SDMMAC to validate
     * @param string       $sdmFileReadKey MAC calculation key
     * @param null|EncMode $mode           Encryption mode
     *
     * @return array{encryption_mode: EncMode, uid: string, read_ctr: int}
     *
     * @throws ValidationException if MAC is invalid
     */
    public function validatePlainSun(
        string $uid,
        string $readCtr,
        string $sdmmac,
        string $sdmFileReadKey,
        ?EncMode $mode = null,
    ): array {
        if (null === $mode) {
            $mode = EncMode::AES;
        }

        if (EncMode::LRP === $mode) {
            throw new \RuntimeException('LRP mode is not supported');
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

        throw new DecryptionException('Unsupported encryption mode');
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
        $mode = $this->getEncryptionMode($piccEncData);

        if (EncMode::LRP === $mode) {
            throw new \RuntimeException('LRP mode is not supported');
        }

        // AES mode - decrypt using CBC with zero IV
        $plaintext = $this->cipher->decrypt($piccEncData, $sdmMetaReadKey, str_repeat("\x00", 16));

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

        // Validate UID length - only 7-byte UIDs are supported by NTAG 424 DNA
        if (self::PICC_SUPPORTED_UID_LENGTH !== $uidLength) {
            // Fake SDMMAC calculation to avoid potential timing attacks
            $this->calculateSdmmac($paramMode, $sdmFileReadKey(str_repeat("\x00", 7)), str_repeat("\x00", 10), $encFileData, $mode);

            throw new DecryptionException('Unsupported UID length');
        }

        if ($uidMirroringEn) {
            $uid = substr($plaintext, $offset, $uidLength);
            $dataStream .= $uid;
            $offset += $uidLength;
        }

        if ($sdmReadCtrEn) {
            $readCtr = substr($plaintext, $offset, 3);
            $dataStream .= $readCtr;
            $unpacked = unpack('V', $readCtr."\x00");
            if (false === $unpacked) {
                throw new DecryptionException('Failed to unpack read counter');
            }
            $readCtrNum = $unpacked[1]; // little-endian 3-byte to int
        }

        if (null === $uid) {
            throw new DecryptionException('UID cannot be null');
        }

        $fileKey = $sdmFileReadKey($uid);

        $calculatedMac = $this->calculateSdmmac($paramMode, $fileKey, $dataStream, $encFileData, $mode);

        if (!\hash_equals($sdmmac, $calculatedMac)) {
            throw new ValidationException('Message is not properly signed - invalid MAC');
        }

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
