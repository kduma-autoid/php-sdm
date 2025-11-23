<?php

declare(strict_types=1);

namespace KDuma\SDM\PICC;

/**
 * PICC (Proximity Integrated Circuit Card) data structure.
 */
class PICCData
{
    public function __construct(
        private readonly string $uid,
        private readonly int $readCounter,
    ) {}

    public function getUid(): string
    {
        return $this->uid;
    }

    public function getReadCounter(): int
    {
        return $this->readCounter;
    }

    /**
     * Parse encrypted PICC data.
     *
     * @param string $encryptedData Encrypted PICC data
     */
    public static function fromEncrypted(string $encryptedData): self
    {
        // TODO: Implementation
        throw new \RuntimeException('Not implemented yet');
    }
}
