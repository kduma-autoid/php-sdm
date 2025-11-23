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
     * Encrypt data using ECB mode.
     *
     * @param string $data Data to encrypt
     * @param string $key  Encryption key
     *
     * @return string Encrypted data
     */
    public function encryptECB(string $data, string $key): string;
}
