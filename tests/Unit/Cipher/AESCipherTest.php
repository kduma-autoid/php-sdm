<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\Cipher;

use KDuma\SDM\Cipher\AESCipher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(AESCipher::class)]
final class AESCipherTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $cipher = new AESCipher();

        $this->assertInstanceOf(AESCipher::class, $cipher);
    }

    /**
     * Test CMAC with NIST SP 800-38B test vector (empty message).
     */
    public function testCmacEmptyMessage(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $this->assertNotFalse($key);

        $result = $cipher->cmac('', $key);

        $this->assertSame(
            'bb1d6929e95937287fa37d129b756746',
            bin2hex($result),
            'CMAC of empty message should match NIST test vector',
        );
    }

    /**
     * Test CMAC with NIST SP 800-38B test vector (16 byte message).
     */
    public function testCmac16ByteMessage(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d7e117393172a');
        $this->assertNotFalse($key);
        $this->assertNotFalse($message);

        $result = $cipher->cmac($message, $key);

        $this->assertSame(
            '070a16b46b4d4144f79bdd9dd04a287c',
            bin2hex($result),
            'CMAC of 16 byte message should match NIST test vector',
        );
    }

    /**
     * Test CMAC with incomplete block that requires padding (10 bytes).
     */
    public function testCmacIncompleteBlock(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d');
        $this->assertNotFalse($key);
        $this->assertNotFalse($message);

        $result = $cipher->cmac($message, $key);

        // This should exercise the padding path (lines 47-49 in AESCipher)
        $this->assertSame(16, strlen($result));
    }

    /**
     * Test CMAC with NIST SP 800-38B test vector (40 byte message).
     * This tests multi-block processing with incomplete last block.
     */
    public function testCmac40ByteMessage(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411');
        $this->assertNotFalse($key);
        $this->assertNotFalse($message);

        $result = $cipher->cmac($message, $key);

        $this->assertSame(
            'dfa66747de9ae63030ca32611497c827',
            bin2hex($result),
            'CMAC of 40 byte message should match NIST test vector',
        );
    }

    /**
     * Test CMAC with 32 byte message (2 complete blocks).
     * This tests multi-block processing with complete last block.
     */
    public function testCmac32ByteMessage(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51');
        $this->assertNotFalse($key);
        $this->assertNotFalse($message);

        $result = $cipher->cmac($message, $key);

        $this->assertSame(
            'ce0cbf1738f4df6428b1d93bf12081c9',
            bin2hex($result),
            'CMAC of 32 byte message should match computed CMAC',
        );
    }

    /**
     * Test CMAC with 64 byte message (4 complete blocks).
     * This tests multi-block processing with more iterations.
     */
    public function testCmac64ByteMessage(): void
    {
        $cipher = new AESCipher();
        $key = hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $message = hex2bin('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710');
        $this->assertNotFalse($key);
        $this->assertNotFalse($message);

        $result = $cipher->cmac($message, $key);

        $this->assertSame(
            '51f0bebf7e3b9d92fc49741779363cfe',
            bin2hex($result),
            'CMAC of 64 byte message should match NIST test vector',
        );
    }

    /**
     * Test that encrypt method throws RuntimeException (not yet implemented).
     */
    public function testEncryptNotImplemented(): void
    {
        $cipher = new AESCipher();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Not implemented yet');

        $cipher->encrypt('data', 'key1234567890123', '1234567890123456');
    }

    /**
     * Test that decrypt method throws RuntimeException (not yet implemented).
     */
    public function testDecryptNotImplemented(): void
    {
        $cipher = new AESCipher();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Not implemented yet');

        $cipher->decrypt('data', 'key1234567890123', '1234567890123456');
    }
}
