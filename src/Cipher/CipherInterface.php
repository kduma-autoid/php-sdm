<?php

declare(strict_types=1);

namespace KDuma\SDM\Cipher;

/**
 * Interface for cryptographic operations.
 */
interface CipherInterface
{
    /**
     * Encrypt data.
     *
     * @param string $data Data to encrypt
     * @param string $key  Encryption key
     * @param string $iv   Initialization vector
     *
     * @return string Encrypted data
     */
    public function encrypt(string $data, string $key, string $iv): string;

    /**
     * Decrypt data.
     *
     * @param string $data Data to decrypt
     * @param string $key  Decryption key
     * @param string $iv   Initialization vector
     *
     * @return string Decrypted data
     */
    public function decrypt(string $data, string $key, string $iv): string;

    /**
     * Generate CMAC.
     *
     * @param string $data Data to authenticate
     * @param string $key  MAC key
     *
     * @return string CMAC value
     */
    public function cmac(string $data, string $key): string;

    /**
     * Encrypt data using AES-128-ECB mode without padding.
     *
     * ECB (Electronic Codebook) mode encrypts each block independently without
     * an initialization vector. This makes it deterministic but less secure for
     * general use. It should only be used for specific cryptographic operations.
     *
     * @param string $data The plaintext data to encrypt (must be 16-byte aligned)
     * @param string $key  The encryption key (16 bytes for AES-128)
     *
     * @return string The encrypted ciphertext (same length as input)
     *
     * @throws \RuntimeException if encryption fails
     */
    public function encryptECB(string $data, string $key): string;
}
