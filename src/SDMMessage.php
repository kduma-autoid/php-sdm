<?php

declare(strict_types=1);

namespace KDuma\SDM;

use KDuma\SDM\Exceptions\InvalidMessageException;

/**
 * Represents a Secure Dynamic Messaging (SDM) message from an NTAG 424 DNA tag.
 * 
 * This class handles parsing and validating SDM messages that contain:
 * - PICC data (tag identifier information)
 * - Encrypted data (containing tap counter and optionally file data)
 * - CMAC signature for authentication
 */
class SDMMessage
{
    /**
     * Create a new SDM message instance.
     *
     * @param string $piccData The PICC data (typically UID mirror)
     * @param string $encryptedData The encrypted portion containing counter and optional file data
     * @param string $cmac The CMAC signature for message authentication
     */
    public function __construct(
        private readonly string $piccData,
        private readonly string $encryptedData,
        private readonly string $cmac
    ) {
    }

    /**
     * Create SDM message from URL string.
     *
     * @param string $url The full URL containing SDM parameters
     * @return self
     * @throws InvalidMessageException If URL cannot be parsed
     */
    public static function fromUrl(string $url): self
    {
        // TODO: Implementation will be added later
        throw new InvalidMessageException('Method not yet implemented');
    }

    /**
     * Create SDM message from array of parameters.
     *
     * @param array<string, string> $params Associative array with 'picc_data', 'enc', and 'cmac' keys
     * @return self
     * @throws InvalidMessageException If required parameters are missing
     */
    public static function fromArray(array $params): self
    {
        // TODO: Implementation will be added later
        throw new InvalidMessageException('Method not yet implemented');
    }

    /**
     * Get the PICC data.
     *
     * @return string
     */
    public function getPiccData(): string
    {
        return $this->piccData;
    }

    /**
     * Get the encrypted data.
     *
     * @return string
     */
    public function getEncryptedData(): string
    {
        return $this->encryptedData;
    }

    /**
     * Get the CMAC signature.
     *
     * @return string
     */
    public function getCmac(): string
    {
        return $this->cmac;
    }
}
