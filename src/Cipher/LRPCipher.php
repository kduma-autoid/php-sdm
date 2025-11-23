<?php

declare(strict_types=1);

namespace KDuma\SDM\Cipher;

/**
 * LRP (Leakage Resilient Primitive) cipher implementation for NTAG DNA 424
 *
 * LRP is an alternative encryption mode to AES, designed to be more resilient
 * against side-channel attacks.
 */
class LRPCipher implements CipherInterface
{
    /**
     * {@inheritdoc}
     */
    public function encrypt(string $data, string $key, string $iv): string
    {
        // TODO: Implementation
        throw new \RuntimeException('LRP encryption not implemented yet');
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $data, string $key, string $iv): string
    {
        // TODO: Implementation
        throw new \RuntimeException('LRP decryption not implemented yet');
    }

    /**
     * {@inheritdoc}
     */
    public function cmac(string $data, string $key): string
    {
        // TODO: Implementation
        throw new \RuntimeException('LRP CMAC not implemented yet');
    }
}
