<?php

declare(strict_types=1);

namespace KDuma\SDM\Cipher;

/**
 * AES cipher implementation for NTAG DNA 424.
 */
class AESCipher implements CipherInterface
{
    public function encrypt(string $data, string $key, string $iv): string
    {
        $encrypted = openssl_encrypt($data, 'AES-128-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);

        if (false === $encrypted) {
            throw new \RuntimeException('Failed to encrypt data');
        }

        return $encrypted;
    }

    public function decrypt(string $data, string $key, string $iv): string
    {
        $decrypted = openssl_decrypt($data, 'AES-128-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING, $iv);

        if (false === $decrypted) {
            throw new \RuntimeException('Failed to decrypt data');
        }

        return $decrypted;
    }

    public function encryptECB(string $data, string $key): string
    {
        $encrypted = openssl_encrypt($data, 'AES-128-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);

        if (false === $encrypted) {
            throw new \RuntimeException('Failed to encrypt data in ECB mode');
        }

        return $encrypted;
    }

    public function cmac(string $data, string $key): string
    {
        $blockSize = 16; // AES block size in bytes

        // Generate subkeys
        [$k1, $k2] = $this->generateSubkeys($key, $blockSize);

        // Prepare the last block
        $length = strlen($data);

        if (0 === $length) {
            // Empty message: use padded empty block
            $numBlocks = 1;
            $lastBlock = $this->pad('', $blockSize);
            $lastBlock = $this->xorStrings($lastBlock, $k2);
        } else {
            $numBlocks = (int) ceil($length / $blockSize);
            $lastBlockComplete = (0 === $length % $blockSize);

            if ($lastBlockComplete) {
                $lastBlock = substr($data, ($numBlocks - 1) * $blockSize, $blockSize);
                $lastBlock = $this->xorStrings($lastBlock, $k1);
            } else {
                $lastBlock = substr($data, ($numBlocks - 1) * $blockSize);
                $lastBlock = $this->pad($lastBlock, $blockSize);
                $lastBlock = $this->xorStrings($lastBlock, $k2);
            }
        }

        // Process blocks
        $x = str_repeat("\x00", $blockSize);

        for ($i = 0; $i < $numBlocks - 1; ++$i) {
            $block = substr($data, $i * $blockSize, $blockSize);
            $x = $this->xorStrings($x, $block);
            $encrypted = openssl_encrypt($x, 'AES-128-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);

            if (false === $encrypted) {
                throw new \RuntimeException('Failed to encrypt data during CMAC calculation');
            }

            $x = $encrypted;
        }

        $x = $this->xorStrings($x, $lastBlock);
        $mac = openssl_encrypt($x, 'AES-128-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);

        if (false === $mac) {
            throw new \RuntimeException('Failed to generate CMAC');
        }

        return $mac;
    }

    /**
     * Generate CMAC subkeys K1 and K2.
     *
     * @return array{0: string, 1: string}
     */
    private function generateSubkeys(string $key, int $blockSize): array
    {
        // L = AES-128(K, 0^128)
        $zero = str_repeat("\x00", $blockSize);
        $l = openssl_encrypt($zero, 'AES-128-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);

        if (false === $l) {
            throw new \RuntimeException('Failed to encrypt data for CMAC subkey generation');
        }

        // K1 = L << 1
        $k1 = $this->leftShift($l);

        // If MSB(L) = 1, K1 = K1 XOR Rb
        if ((ord($l[0]) & 0x80) !== 0) {
            $k1 = $this->xorStrings($k1, $this->getRb($blockSize));
        }

        // K2 = K1 << 1
        $k2 = $this->leftShift($k1);

        // If MSB(K1) = 1, K2 = K2 XOR Rb
        if ((ord($k1[0]) & 0x80) !== 0) {
            $k2 = $this->xorStrings($k2, $this->getRb($blockSize));
        }

        return [$k1, $k2];
    }

    /**
     * Left shift one bit.
     */
    private function leftShift(string $input): string
    {
        $length = strlen($input);
        $output = '';
        $carry = 0;

        for ($i = $length - 1; $i >= 0; --$i) {
            $byte = ord($input[$i]);
            $output = chr((($byte << 1) | $carry) & 0xFF).$output;
            $carry = ($byte & 0x80) ? 1 : 0;
        }

        return $output;
    }

    /**
     * XOR two strings of equal length.
     *
     * @throws \InvalidArgumentException if strings have different lengths
     */
    private function xorStrings(string $a, string $b): string
    {
        $lengthA = strlen($a);
        $lengthB = strlen($b);

        if ($lengthA !== $lengthB) {
            throw new \InvalidArgumentException(
                sprintf('Cannot XOR strings of different lengths: %d vs %d bytes', $lengthA, $lengthB),
            );
        }

        return $a ^ $b;
    }

    /**
     * Pad the input according to CMAC specification (10* padding).
     */
    private function pad(string $input, int $blockSize): string
    {
        $padLength = $blockSize - strlen($input);

        return $input."\x80".str_repeat("\x00", $padLength - 1);
    }

    /**
     * Get Rb constant for CMAC (0x87 for AES-128).
     */
    private function getRb(int $blockSize): string
    {
        return str_repeat("\x00", $blockSize - 1)."\x87";
    }
}
