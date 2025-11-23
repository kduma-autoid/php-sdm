<?php

declare(strict_types=1);

namespace KDuma\SDM\Cipher;

use KDuma\SDM\Exceptions\DecryptionException;

/**
 * AES cipher implementation for NTAG DNA 424
 */
class AESCipher implements CipherInterface
{
    /**
     * {@inheritdoc}
     */
    public function encrypt(string $data, string $key, string $iv): string
    {
        $encrypted = openssl_encrypt(
            $data,
            'aes-128-cbc',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );

        if ($encrypted === false) {
            throw new DecryptionException('AES encryption failed');
        }

        return $encrypted;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $data, string $key, string $iv): string
    {
        $decrypted = openssl_decrypt(
            $data,
            'aes-128-cbc',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );

        if ($decrypted === false) {
            throw new DecryptionException('AES decryption failed');
        }

        return $decrypted;
    }

    /**
     * {@inheritdoc}
     */
    public function cmac(string $data, string $key): string
    {
        // AES-CMAC implementation based on NIST SP 800-38B
        // Constants for CMAC
        $const_Rb = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x87";
        $blockSize = 16;

        // Generate subkeys
        $L = $this->encrypt(str_repeat("\x00", $blockSize), $key, str_repeat("\x00", $blockSize));
        $K1 = $this->leftShift($L);
        if (ord($L[0]) & 0x80) {
            $K1 = $this->xorStrings($K1, $const_Rb);
        }

        $K2 = $this->leftShift($K1);
        if (ord($K1[0]) & 0x80) {
            $K2 = $this->xorStrings($K2, $const_Rb);
        }

        // Pad data if necessary
        $dataLength = strlen($data);

        // Determine if we need to pad
        $isComplete = ($dataLength > 0) && ($dataLength % $blockSize === 0);

        if ($isComplete) {
            // Data is a non-zero multiple of block size
            $numBlocks = $dataLength / $blockSize;
        } else {
            // Data is empty or not a multiple of block size - will need padding
            $numBlocks = (int) ceil($dataLength / $blockSize);
            if ($numBlocks === 0) {
                $numBlocks = 1;
            }
        }

        // Process all complete blocks except the last
        $Y = str_repeat("\x00", $blockSize);

        for ($i = 0; $i < $numBlocks - 1; $i++) {
            $block = substr($data, $i * $blockSize, $blockSize);
            $Y = $this->xorStrings($Y, $block);
            $Y = $this->encrypt($Y, $key, str_repeat("\x00", $blockSize));
        }

        // Process last block
        if ($isComplete) {
            // Last block is complete - XOR with K1
            $lastBlock = substr($data, ($numBlocks - 1) * $blockSize, $blockSize);
            $lastBlock = $this->xorStrings($lastBlock, $K1);
        } else {
            // Last block is incomplete or empty - pad with 10...0 and XOR with K2
            $lastBlock = substr($data, ($numBlocks - 1) * $blockSize);
            $lastBlock .= "\x80" . str_repeat("\x00", $blockSize - strlen($lastBlock) - 1);
            $lastBlock = $this->xorStrings($lastBlock, $K2);
        }

        $Y = $this->xorStrings($Y, $lastBlock);
        $mac = $this->encrypt($Y, $key, str_repeat("\x00", $blockSize));

        return $mac;
    }

    /**
     * Derive a key using AES-based key derivation
     *
     * @param string $masterKey Master key for derivation
     * @param string $diversificationInput Diversification input
     * @return string Derived key
     */
    public function deriveKey(string $masterKey, string $diversificationInput): string
    {
        // Pad diversification input to 16 bytes
        $input = str_pad($diversificationInput, 16, "\x00");

        // Use CMAC for key derivation
        return $this->cmac($input, $masterKey);
    }

    /**
     * Left shift a byte string by one bit
     *
     * @param string $data Data to shift
     * @return string Shifted data
     */
    private function leftShift(string $data): string
    {
        $result = '';
        $overflow = 0;

        for ($i = strlen($data) - 1; $i >= 0; $i--) {
            $byte = ord($data[$i]);
            $result = chr(($byte << 1 | $overflow) & 0xFF) . $result;
            $overflow = ($byte & 0x80) ? 1 : 0;
        }

        return $result;
    }

    /**
     * XOR two byte strings
     *
     * @param string $a First string
     * @param string $b Second string
     * @return string XORed result
     */
    private function xorStrings(string $a, string $b): string
    {
        $length = max(strlen($a), strlen($b));
        $a = str_pad($a, $length, "\x00");
        $b = str_pad($b, $length, "\x00");

        $result = '';
        for ($i = 0; $i < $length; $i++) {
            $result .= chr(ord($a[$i]) ^ ord($b[$i]));
        }

        return $result;
    }
}
