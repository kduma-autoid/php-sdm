<?php

declare(strict_types=1);

namespace KDuma\SDM\SUN;

/**
 * SUN (Secure Unique NFC) message structure
 */
class SUNMessage
{
    public function __construct(
        private readonly string $encPICCData,
        private readonly string $encFileData,
        private readonly string $cmac,
    ) {
    }

    public function getEncPICCData(): string
    {
        return $this->encPICCData;
    }

    public function getEncFileData(): string
    {
        return $this->encFileData;
    }

    public function getCmac(): string
    {
        return $this->cmac;
    }

    /**
     * Parse SUN message from URL parameters
     *
     * @param array<string, string> $params URL parameters
     * @return self
     */
    public static function fromUrlParams(array $params): self
    {
        // TODO: Implementation
        throw new \RuntimeException('Not implemented yet');
    }
}
