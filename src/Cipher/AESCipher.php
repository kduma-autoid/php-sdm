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
        // TODO: Implementation
        throw new \RuntimeException('Not implemented yet');
    }
}
