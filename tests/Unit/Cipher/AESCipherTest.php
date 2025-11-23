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
}
