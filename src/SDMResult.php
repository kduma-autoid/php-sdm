<?php

declare(strict_types=1);

namespace KDuma\SDM;

/**
 * Contains the decrypted and validated data from an SDM message.
 * 
 * This class provides access to:
 * - Tag UID (unique identifier)
 * - Tap counter (increments with each read)
 * - Optional file data
 * - Validation status
 */
class SDMResult
{
    /**
     * Create a new SDM result instance.
     *
     * @param string $uid The tag's unique identifier
     * @param int $tapCounter The tap counter value
     * @param bool $valid Whether the message signature was valid
     * @param string|null $fileData Optional file data from the tag
     */
    public function __construct(
        private readonly string $uid,
        private readonly int $tapCounter,
        private readonly bool $valid,
        private readonly ?string $fileData = null
    ) {
    }

    /**
     * Get the tag's unique identifier.
     *
     * @return string The UID in hexadecimal format
     */
    public function getUid(): string
    {
        return $this->uid;
    }

    /**
     * Get the tap counter value.
     * 
     * The tap counter increments with each read operation and can be used
     * to detect replay attacks.
     *
     * @return int The tap counter value
     */
    public function getTapCounter(): int
    {
        return $this->tapCounter;
    }

    /**
     * Check if the message signature was valid.
     *
     * @return bool True if the CMAC signature was valid
     */
    public function isValid(): bool
    {
        return $this->valid;
    }

    /**
     * Get the optional file data from the tag.
     *
     * @return string|null The file data, or null if not present
     */
    public function getFileData(): ?string
    {
        return $this->fileData;
    }

    /**
     * Get the file data decoded as UTF-8 string.
     *
     * @return string|null The decoded file data, or null if not present
     */
    public function getDecodedFileData(): ?string
    {
        if ($this->fileData === null) {
            return null;
        }

        return mb_convert_encoding($this->fileData, 'UTF-8', 'UTF-8');
    }

    /**
     * Convert result to array representation.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'uid' => $this->uid,
            'tap_counter' => $this->tapCounter,
            'valid' => $this->valid,
            'file_data' => $this->fileData,
        ];
    }
}
