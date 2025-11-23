<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\Cipher;

use KDuma\SDM\Cipher\AESCipher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Additional method coverage tests for AESCipher class.
 *
 * @internal
 */
#[CoversClass(AESCipher::class)]
final class AESCipherMethodsTest extends TestCase
{
    /**
     * Test constructor creates instance.
     */
    public function testConstructor(): void
    {
        $cipher = new AESCipher();

        $this->assertInstanceOf(AESCipher::class, $cipher);
    }

    /**
     * Test encrypt with 16-byte blocks.
     */
    public function testEncryptWith16ByteBlocks(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $iv = hex2bin('00000000000000000000000000000000');
        $plaintext = hex2bin('6bc1bee22e409f96e93d7e117393172a');

        $encrypted = $cipher->encrypt($plaintext, $key, $iv);

        $this->assertSame(16, strlen($encrypted));
    }

    /**
     * Test decrypt with 16-byte blocks.
     */
    public function testDecryptWith16ByteBlocks(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $iv = hex2bin('00000000000000000000000000000000');
        $plaintext = hex2bin('6bc1bee22e409f96e93d7e117393172a');

        $encrypted = $cipher->encrypt($plaintext, $key, $iv);
        $decrypted = $cipher->decrypt($encrypted, $key, $iv);

        $this->assertSame($plaintext, $decrypted);
    }

    /**
     * Test encryptECB with zero block.
     */
    public function testEncryptECBWithZeroBlock(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $plaintext = hex2bin('00000000000000000000000000000000');

        $encrypted = $cipher->encryptECB($plaintext, $key);

        $this->assertSame(16, strlen($encrypted));
    }

    /**
     * Test encryptECB produces consistent output.
     */
    public function testEncryptECBConsistentOutput(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('00000000000000000000000000000000');
        $plaintext = hex2bin('00000000000000000000000000000000');

        $encrypted1 = $cipher->encryptECB($plaintext, $key);
        $encrypted2 = $cipher->encryptECB($plaintext, $key);

        $this->assertSame($encrypted1, $encrypted2);
    }

    /**
     * Test CMAC with single complete block.
     */
    public function testCmacSingleCompleteBlock(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d7e117393172a');

        $mac = $cipher->cmac($message, $key);

        $this->assertSame(16, strlen($mac));
        $this->assertSame('070a16b46b4d4144f79bdd9dd04a287c', bin2hex($mac));
    }

    /**
     * Test CMAC with multiple complete blocks.
     */
    public function testCmacMultipleCompleteBlocks(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51');

        $mac = $cipher->cmac($message, $key);

        $this->assertSame(16, strlen($mac));
    }

    /**
     * Test CMAC with incomplete last block.
     */
    public function testCmacIncompleteLastBlock(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d');

        $mac = $cipher->cmac($message, $key);

        $this->assertSame(16, strlen($mac));
    }

    /**
     * Test CMAC with various message lengths.
     */
    public function testCmacVariousLengths(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');

        // 1 byte
        $mac1 = $cipher->cmac('a', $key);
        $this->assertSame(16, strlen($mac1));

        // 15 bytes
        $mac15 = $cipher->cmac(str_repeat('a', 15), $key);
        $this->assertSame(16, strlen($mac15));

        // 17 bytes
        $mac17 = $cipher->cmac(str_repeat('a', 17), $key);
        $this->assertSame(16, strlen($mac17));

        // 31 bytes
        $mac31 = $cipher->cmac(str_repeat('a', 31), $key);
        $this->assertSame(16, strlen($mac31));

        // 33 bytes
        $mac33 = $cipher->cmac(str_repeat('a', 33), $key);
        $this->assertSame(16, strlen($mac33));
    }

    /**
     * Test encrypt/decrypt round-trip with various data sizes.
     */
    public function testEncryptDecryptRoundTrip(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $iv = hex2bin('00000000000000000000000000000000');

        $testData = [
            hex2bin('00000000000000000000000000000000'),
            hex2bin('ffffffffffffffffffffffffffffffff'),
            hex2bin('6bc1bee22e409f96e93d7e117393172a'),
            str_repeat('a', 16),
        ];

        foreach ($testData as $plaintext) {
            $encrypted = $cipher->encrypt($plaintext, $key, $iv);
            $decrypted = $cipher->decrypt($encrypted, $key, $iv);

            $this->assertSame($plaintext, $decrypted);
        }
    }
}
