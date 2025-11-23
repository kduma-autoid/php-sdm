<?php

declare(strict_types=1);

namespace KDuma\SDM;

/**
 * Interface for NTAG DNA 424 Secure Dynamic Messaging operations.
 */
interface SDMInterface
{
    /**
     * Decrypt and validate an SDM message.
     *
     * @param string $encData     Encrypted PICC data
     * @param string $encFileData Encrypted file data
     * @param string $cmac        CMAC for authentication
     *
     * @return array<string, mixed> Decrypted data
     */
    public function decrypt(string $encData, string $encFileData, string $cmac): array;

    /**
     * Validate plain SUN message authentication.
     *
     * Validates a plain (unencrypted) SUN message by checking its SDMMAC.
     * The data must contain UID (7 bytes) followed by SDMReadCtr (3 bytes).
     *
     * @param string $data The plain SUN data: UID (7 bytes) + ReadCtr (3 bytes), exactly 10 bytes
     * @param string $cmac The SDMMAC to validate against (8 bytes)
     *
     * @return bool True if the SDMMAC is valid and data format is correct, false otherwise
     */
    public function validate(string $data, string $cmac): bool;
}
