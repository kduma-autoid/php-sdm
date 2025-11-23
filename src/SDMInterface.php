<?php

declare(strict_types=1);

namespace KDuma\SDM;

/**
 * Interface for NTAG DNA 424 Secure Dynamic Messaging operations
 */
interface SDMInterface
{
    /**
     * Decrypt and validate an SDM message
     *
     * @param string $encData Encrypted PICC data
     * @param string $encFileData Encrypted file data
     * @param string $cmac CMAC for authentication
     * @return array<string, mixed> Decrypted data
     */
    public function decrypt(string $encData, string $encFileData, string $cmac): array;

    /**
     * Validate SDM message authentication
     *
     * @param string $data Data to validate
     * @param string $cmac CMAC to check against
     * @return bool True if valid
     */
    public function validate(string $data, string $cmac): bool;
}
