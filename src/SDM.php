<?php

declare(strict_types=1);

namespace KDuma\SDM;

/**
 * Main class for NTAG DNA 424 Secure Dynamic Messaging operations
 */
class SDM implements SDMInterface
{
    public function __construct(
        private readonly string $encKey,
        private readonly string $macKey,
    ) {
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $encData, string $encFileData, string $cmac): array
    {
        // TODO: Implementation
        throw new \RuntimeException('Not implemented yet');
    }

    /**
     * {@inheritdoc}
     */
    public function validate(string $data, string $cmac): bool
    {
        // TODO: Implementation
        throw new \RuntimeException('Not implemented yet');
    }
}
