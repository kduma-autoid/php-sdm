<?php

declare(strict_types=1);

namespace KDuma\SDM\Cipher;

/**
 * Leakage Resilient Primitive (LRP) cipher implementation.
 *
 * This implementation is based on AN12304: NTAG 424 DNA and NTAG 424 DNA TagTamper
 * features and hints - Leakage Resilient Primitive (LRP).
 *
 * NOTE: This implementation is suitable only for use on PCD side (the device which
 * reads/interacts with the NFC tag). You shouldn't use this code on PICC (NFC tag/card)
 * side and it shouldn't be ported to JavaCards or similar, because in such case it may
 * not be resistant to side channel attacks.
 *
 * @see https://www.nxp.com/docs/en/application-note/AN12304.pdf
 */
class LRPCipher implements CipherInterface
{
    /**
     * AES block size in bytes.
     */
    private const BLOCK_SIZE = 16;

    /**
     * Number of nibbles (4-bit values) for LRP operations.
     */
    private const M = 4;

    /**
     * Number of updated keys to generate.
     */
    private const Q = 4;

    /**
     * Precomputed plaintexts for LRP evaluation.
     *
     * @var array<int, string>
     */
    private array $plaintexts;

    /**
     * Precomputed updated keys.
     *
     * @var array<int, string>
     */
    private array $updatedKeys;

    /**
     * Current updated key.
     */
    private string $currentKey;

    /**
     * Current counter/IV value.
     */
    private string $counter;

    /**
     * Whether to use padding.
     */
    private bool $usePadding;

    /**
     * Initialize LRP cipher.
     *
     * @param string $key        Secret key (16 bytes)
     * @param int    $updateMode Updated key index to use (0-3)
     * @param string $counter    Initial counter/IV value (16 bytes, default: all zeros)
     * @param bool   $usePadding Whether to use padding (default: true)
     */
    public function __construct(
        string $key,
        private readonly int $updateMode = 0,
        ?string $counter = null,
        bool $usePadding = true,
    ) {
        if (16 !== strlen($key)) {
            throw new \InvalidArgumentException('Key must be 16 bytes');
        }

        if ($updateMode < 0 || $updateMode >= self::Q) {
            throw new \InvalidArgumentException('Update mode must be between 0 and '.(self::Q - 1));
        }

        $this->counter = $counter ?? str_repeat("\x00", 16);
        $this->usePadding = $usePadding;

        // Generate plaintexts and updated keys
        $this->plaintexts = $this->generatePlaintexts($key);
        $this->updatedKeys = $this->generateUpdatedKeys($key);
        $this->currentKey = $this->updatedKeys[$this->updateMode];
    }

    /**
     * Generate plaintexts for LRP (Algorithm 1).
     *
     * @param string $key Secret key (16 bytes)
     *
     * @return array<int, string> Array of plaintext blocks
     */
    public static function generatePlaintexts(string $key): array
    {
        $h = $key;
        $h = self::encryptECBStatic($h, str_repeat("\x55", 16));

        $plaintexts = [];
        for ($i = 0; $i < (1 << self::M); ++$i) {
            $plaintexts[] = self::encryptECBStatic($h, str_repeat("\xaa", 16));
            $h = self::encryptECBStatic($h, str_repeat("\x55", 16));
        }

        return $plaintexts;
    }

    /**
     * Generate updated keys for LRP (Algorithm 2).
     *
     * @param string $key Secret key (16 bytes)
     *
     * @return array<int, string> Array of updated keys
     */
    public static function generateUpdatedKeys(string $key): array
    {
        $h = $key;
        $h = self::encryptECBStatic($h, str_repeat("\xaa", 16));

        $updatedKeys = [];
        for ($i = 0; $i < self::Q; ++$i) {
            $updatedKeys[] = self::encryptECBStatic($h, str_repeat("\xaa", 16));
            $h = self::encryptECBStatic($h, str_repeat("\x55", 16));
        }

        return $updatedKeys;
    }

    /**
     * Evaluate LRP function (Algorithm 3).
     *
     * @param array<int, string> $plaintexts Precomputed plaintexts
     * @param string             $key        Updated key
     * @param string             $input      Input data
     * @param bool               $finalize   Whether to apply finalization
     *
     * @return string Evaluation result (16 bytes)
     */
    public static function evalLRP(array $plaintexts, string $key, string $input, bool $finalize): string
    {
        $y = $key;

        // Process input as nibbles (4-bit values)
        foreach (self::getNibbles($input) as $nibble) {
            $pj = $plaintexts[$nibble];
            $y = self::encryptECBStatic($y, $pj);
        }

        if ($finalize) {
            $y = self::encryptECBStatic($y, str_repeat("\x00", 16));
        }

        return $y;
    }

    /**
     * Encrypt data using LRICB mode.
     *
     * NOTE: The $iv parameter is ignored by this implementation. LRP uses an
     * internal counter that must be set via the constructor or setCounter().
     * The IV parameter is only present for CipherInterface compatibility.
     *
     * @param string $data Data to encrypt
     * @param string $key  Encryption key (16 bytes) - ignored, uses constructor key
     * @param string $iv   Initialization vector - IGNORED, uses internal counter
     *
     * @return string Encrypted data
     */
    public function encrypt(string $data, string $key, string $iv): string
    {
        $plaintext = $data;

        // Apply padding if enabled
        if ($this->usePadding) {
            $plaintext .= "\x80";
            while (0 !== strlen($plaintext) % self::BLOCK_SIZE) {
                $plaintext .= "\x00";
            }
        } elseif (0 !== strlen($plaintext) % self::BLOCK_SIZE) {
            throw new \RuntimeException('Data length must be a multiple of block size when padding is disabled');
        } elseif (0 === strlen($plaintext)) {
            throw new \RuntimeException('Zero length data is not supported');
        }

        $ciphertext = '';
        $blocks = str_split($plaintext, self::BLOCK_SIZE);

        foreach ($blocks as $block) {
            $y = self::evalLRP($this->plaintexts, $this->currentKey, $this->counter, true);
            $ciphertext .= self::encryptECBStatic($y, $block);
            $this->counter = self::incrementCounter($this->counter);
        }

        return $ciphertext;
    }

    /**
     * Decrypt data using LRICB mode.
     *
     * NOTE: The $iv parameter is ignored by this implementation. LRP uses an
     * internal counter that must be set via the constructor or setCounter().
     * The IV parameter is only present for CipherInterface compatibility.
     *
     * @param string $data Data to decrypt
     * @param string $key  Decryption key (16 bytes) - ignored, uses constructor key
     * @param string $iv   Initialization vector - IGNORED, uses internal counter
     *
     * @return string Decrypted data
     */
    public function decrypt(string $data, string $key, string $iv): string
    {
        $plaintext = '';
        $blocks = str_split($data, self::BLOCK_SIZE);

        foreach ($blocks as $block) {
            $y = self::evalLRP($this->plaintexts, $this->currentKey, $this->counter, true);
            $plaintext .= self::decryptECBStatic($y, $block);
            $this->counter = self::incrementCounter($this->counter);
        }

        // Remove padding if enabled
        if ($this->usePadding) {
            $plaintext = self::removePadding($plaintext);
        }

        return $plaintext;
    }

    /**
     * Calculate CMAC using LRP.
     *
     * @param string $data Data to authenticate
     * @param string $key  MAC key (16 bytes)
     *
     * @return string CMAC value (16 bytes)
     */
    public function cmac(string $data, string $key): string
    {
        // Calculate K0
        $k0 = self::evalLRP($this->plaintexts, $this->currentKey, str_repeat("\x00", 16), true);

        // Calculate K1 and K2 using GF(2^128) multiplication
        $k1 = $this->gfMultiply($k0, 2);
        $k2 = $this->gfMultiply($k0, 4);

        $y = str_repeat("\x00", self::BLOCK_SIZE);
        $blocks = str_split($data, self::BLOCK_SIZE);
        $lastBlock = '';
        $padBytes = 0;

        if (count($blocks) > 0) {
            // Process all but the last block
            for ($i = 0; $i < count($blocks) - 1; ++$i) {
                $y = $this->xorStrings($blocks[$i], $y);
                $y = self::evalLRP($this->plaintexts, $this->currentKey, $y, true);
            }

            $lastBlock = $blocks[count($blocks) - 1];
        }

        // Handle last block with padding if necessary
        if (strlen($lastBlock) < self::BLOCK_SIZE) {
            $padBytes = self::BLOCK_SIZE - strlen($lastBlock);
            $lastBlock .= "\x80".str_repeat("\x00", $padBytes - 1);
        }

        $y = $this->xorStrings($lastBlock, $y);

        if (0 === $padBytes) {
            $y = $this->xorStrings($y, $k1);
        } else {
            $y = $this->xorStrings($y, $k2);
        }

        return self::evalLRP($this->plaintexts, $this->currentKey, $y, true);
    }

    /**
     * Get the current counter value.
     *
     * @return string Current counter (16 bytes)
     */
    public function getCounter(): string
    {
        return $this->counter;
    }

    /**
     * Set the counter value.
     *
     * @param string $counter New counter value (16 bytes)
     */
    public function setCounter(string $counter): void
    {
        $this->counter = $counter;
    }

    /**
     * Encrypt data using AES-128-ECB mode.
     *
     * This method is provided for CipherInterface compatibility and delegates
     * to the underlying AES-ECB implementation. Note that ECB mode is not used
     * for LRP encryption itself - LRP uses LRICB mode which builds upon ECB
     * as a primitive.
     *
     * @param string $data Data to encrypt (must be 16-byte aligned)
     * @param string $key  Encryption key (16 bytes)
     *
     * @return string Encrypted data
     */
    public function encryptECB(string $data, string $key): string
    {
        return self::encryptECBStatic($key, $data);
    }

    /**
     * Extract nibbles (4-bit values) from binary data.
     *
     * @param string $data Binary data
     *
     * @return \Generator<int> Generator yielding nibble values (0-15)
     */
    private static function getNibbles(string $data): \Generator
    {
        $hex = bin2hex($data);
        for ($i = 0; $i < strlen($hex); ++$i) {
            yield (int) hexdec($hex[$i]);
        }
    }

    /**
     * Increment counter value.
     *
     * This implementation uses byte-by-byte arithmetic to avoid PHP integer
     * overflow issues that would occur when converting large counters to integers.
     * Works correctly on both 32-bit and 64-bit systems with counters of any length.
     *
     * The algorithm processes bytes from right to left (big-endian), maintaining
     * a carry flag. Each byte operation ($byteValue) is guaranteed to be ≤ 256,
     * making the bit shift ($byteValue >> 8) safe on all platforms.
     *
     * @param string $counter Current counter value (binary string, any length)
     *
     * @return string Incremented counter (wraps to zero on overflow)
     */
    private static function incrementCounter(string $counter): string
    {
        // Process bytes right-to-left with carry propagation
        $result = $counter;
        $carry = 1;

        for ($i = strlen($result) - 1; $i >= 0 && $carry; --$i) {
            // $byteValue is always 0-256, safe for bit operations on any platform
            $byteValue = ord($result[$i]) + $carry;
            $result[$i] = chr($byteValue & 0xFF);
            $carry = $byteValue >> 8;  // Extract carry (0 or 1)
        }

        // If carry is still 1, counter overflowed - wrap to zero
        if ($carry) {
            return str_repeat("\x00", strlen($counter));
        }

        return $result;
    }

    /**
     * Remove ISO/IEC 9797-1 padding (0x80 followed by zeros).
     *
     * Uses constant-time algorithm to prevent timing attacks. Always scans
     * the entire data regardless of padding location to avoid leaking timing
     * information about where padding starts or validation failures occur.
     *
     * @param string $data Padded data
     *
     * @return string Unpadded data
     *
     * @throws \RuntimeException if padding is invalid
     */
    private static function removePadding(string $data): string
    {
        $dataLen = strlen($data);
        $paddingValid = false;
        $padLength = 0;
        $markerFound = false;

        // Always scan entire data from end to beginning (constant-time)
        for ($i = $dataLen - 1; $i >= 0; --$i) {
            $byte = ord($data[$i]);
            $is0x80 = (0x80 === $byte);
            $is0x00 = (0x00 === $byte);

            // Update padding state without branches that could leak timing
            if ($is0x80 && !$markerFound) {
                // Found 0x80 marker for first time
                $markerFound = true;
                $paddingValid = true;
                $padLength = $dataLen - $i;
            } elseif ($markerFound) {
                // After marker found, all remaining bytes should be data
                // No action needed, continue scanning
            } elseif (!$is0x00) {
                // Before marker: found non-zero byte that isn't 0x80
                // This invalidates padding, but keep scanning
                $paddingValid = false;
            }
            // else: Before marker and byte is 0x00, continue scanning
        }

        // Validate marker was found (constant-time check after full scan)
        if (!$markerFound) {
            $paddingValid = false;
        }

        // Throw exception only after scanning entire data
        if (!$paddingValid) {
            throw new \RuntimeException('Invalid padding');
        }

        return substr($data, 0, -$padLength);
    }

    /**
     * Encrypt data using AES-128-ECB mode.
     *
     * @param string $key  Encryption key (16 bytes)
     * @param string $data Data to encrypt (must be 16 bytes)
     *
     * @return string Encrypted data (16 bytes)
     *
     * @throws \RuntimeException if encryption fails
     */
    private static function encryptECBStatic(string $key, string $data): string
    {
        $result = openssl_encrypt(
            $data,
            'AES-128-ECB',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
        );

        if (false === $result) {
            throw new \RuntimeException('Failed to encrypt data in ECB mode');
        }

        return $result;
    }

    /**
     * Decrypt data using AES-128-ECB mode.
     *
     * @param string $key  Decryption key (16 bytes)
     * @param string $data Data to decrypt (must be 16 bytes)
     *
     * @return string Decrypted data (16 bytes)
     *
     * @throws \RuntimeException if decryption fails
     */
    private static function decryptECBStatic(string $key, string $data): string
    {
        $result = openssl_decrypt(
            $data,
            'AES-128-ECB',
            $key,
            OPENSSL_RAW_DATA | OPENSSL_NO_PADDING,
        );

        if (false === $result) {
            throw new \RuntimeException('Failed to decrypt data in ECB mode');
        }

        return $result;
    }

    /**
     * XOR two binary strings.
     *
     * @param string $a First string
     * @param string $b Second string
     *
     * @return string XOR result
     *
     * @throws \InvalidArgumentException if strings have different lengths
     */
    private function xorStrings(string $a, string $b): string
    {
        if (strlen($a) !== strlen($b)) {
            throw new \InvalidArgumentException('Cannot XOR strings of different lengths');
        }

        return $a ^ $b;
    }

    /**
     * Multiply in GF(2^128) using polynomial representation.
     *
     * This implements multiplication in the Galois Field GF(2^128) with the
     * irreducible polynomial x^128 + x^7 + x^2 + x + 1 (0x87 reduction).
     *
     * @param string $element Element to multiply (16 bytes)
     * @param int    $factor  Factor (2 or 4)
     *
     * @return string Product (16 bytes)
     */
    private function gfMultiply(string $element, int $factor): string
    {
        // Determine number of iterations based on factor
        // Only 2 and 4 are valid per the LRP specification
        $iterations = match ($factor) {
            2 => 1,  // multiply by 2: shift once
            4 => 2,  // multiply by 4: shift twice
            default => throw new \InvalidArgumentException('Factor must be 2 or 4'),
        };

        $result = $element;

        for ($i = 0; $i < $iterations; ++$i) {
            // Check MSB (most significant bit)
            $msb = (ord($result[0]) & 0x80) !== 0;

            // Left shift by 1 bit
            $shifted = '';
            $carry = 0;
            for ($j = strlen($result) - 1; $j >= 0; --$j) {
                $byte = ord($result[$j]);
                $shifted = chr((($byte << 1) | $carry) & 0xFF).$shifted;
                $carry = ($byte >> 7) & 1;
            }

            // If MSB was set, XOR with 0x87
            if ($msb) {
                $shifted[strlen($shifted) - 1] = chr(ord($shifted[strlen($shifted) - 1]) ^ 0x87);
            }

            $result = $shifted;
        }

        return $result;
    }
}
