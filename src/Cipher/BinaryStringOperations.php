<?php

declare(strict_types=1);

namespace KDuma\SDM\Cipher;

/**
 * Common binary string operations for cipher implementations.
 */
trait BinaryStringOperations
{
    /**
     * XOR two binary strings of equal length.
     *
     * @param string $a First binary string
     * @param string $b Second binary string
     *
     * @return string XOR result
     *
     * @throws \InvalidArgumentException if strings have different lengths
     */
    private function xorStrings(string $a, string $b): string
    {
        $lengthA = strlen($a);
        $lengthB = strlen($b);

        if ($lengthA !== $lengthB) {
            throw new \InvalidArgumentException(
                sprintf('Cannot XOR strings of different lengths: %d vs %d bytes', $lengthA, $lengthB),
            );
        }

        return $a ^ $b;
    }
}
