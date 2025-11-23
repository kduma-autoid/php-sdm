<?php

declare(strict_types=1);

namespace KDuma\SDM\Cipher;

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
        // TODO: Implementation
        throw new \RuntimeException('Not implemented yet');
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $data, string $key, string $iv): string
    {
        // TODO: Implementation
        throw new \RuntimeException('Not implemented yet');
    }

    /**
     * {@inheritdoc}
     */
    public function cmac(string $data, string $key): string
    {
        $blockSize = 16; // AES block size in bytes

        // Generate subkeys
        [$k1, $k2] = $this->generateSubkeys($key, $blockSize);

        // Prepare the last block
        $length = strlen($data);

        if ($length === 0) {
            // Empty message: use padded empty block
            $numBlocks = 1;
            $lastBlock = $this->pad('', $blockSize);
            $lastBlock = $this->xorStrings($lastBlock, $k2);
        } else {
            $numBlocks = (int) ceil($length / $blockSize);
            $lastBlockComplete = ($length % $blockSize === 0);

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

        for ($i = 0; $i < $numBlocks - 1; $i++) {
            $block = substr($data, $i * $blockSize, $blockSize);
            $x = $this->xorStrings($x, $block);
            $x = openssl_encrypt($x, 'AES-128-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);
        }

        $x = $this->xorStrings($x, $lastBlock);
        $mac = openssl_encrypt($x, 'AES-128-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);

        return $mac;
    }

    /**
     * Generate CMAC subkeys K1 and K2
     */
    private function generateSubkeys(string $key, int $blockSize): array
    {
        // L = AES-128(K, 0^128)
        $zero = str_repeat("\x00", $blockSize);
        $l = openssl_encrypt($zero, 'AES-128-ECB', $key, OPENSSL_RAW_DATA | OPENSSL_NO_PADDING);

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
     * Left shift one bit
     */
    private function leftShift(string $input): string
    {
        $length = strlen($input);
        $output = '';
        $carry = 0;

        for ($i = $length - 1; $i >= 0; $i--) {
            $byte = ord($input[$i]);
            $output = chr((($byte << 1) | $carry) & 0xFF) . $output;
            $carry = ($byte & 0x80) ? 1 : 0;
        }

        return $output;
    }

    /**
     * XOR two strings of equal length
     */
    private function xorStrings(string $a, string $b): string
    {
        $length = strlen($a);
        $result = '';

        for ($i = 0; $i < $length; $i++) {
            $result .= chr(ord($a[$i]) ^ ord($b[$i]));
        }

        return $result;
    }

    /**
     * Pad the input according to CMAC specification (10* padding)
     */
    private function pad(string $input, int $blockSize): string
    {
        $padLength = $blockSize - strlen($input);
        return $input . "\x80" . str_repeat("\x00", $padLength - 1);
    }

    /**
     * Get Rb constant for CMAC (0x87 for AES-128)
     */
    private function getRb(int $blockSize): string
    {
        return str_repeat("\x00", $blockSize - 1) . "\x87";
    }
}
