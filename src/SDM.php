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

    public function validate(string $data, string $cmac): bool
    {
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

        // AES mode
        $sv2stream = "\x3C\xC3\x00\x01\x00\x80".$piccData;

        // Zero padding till the end of the block
        while (0 !== strlen($sv2stream) % 16) {
            $sv2stream .= "\x00";
        }

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

        // AES mode
        $sv1stream = "\xC3\x3C\x00\x01\x00\x80".$piccData;

        // Zero padding till the end of the block
        while (0 !== strlen($sv1stream) % 16) {
            $sv1stream .= "\x00";
        }

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

        $piccDataTag = $plaintext[0];
        $uidMirroringEn = (ord($piccDataTag) & 0x80) === 0x80;
        $sdmReadCtrEn = (ord($piccDataTag) & 0x40) === 0x40;
        $uidLength = ord($piccDataTag) & 0x0F;

        $uid = null;
        $readCtr = null;
        $readCtrNum = null;
        $fileData = null;
        $dataStream = '';
        $offset = 1;

        // So far this is the only length mentioned by datasheet
        if (0x07 !== $uidLength) {
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
