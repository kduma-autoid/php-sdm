<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\Cipher;

use KDuma\SDM\Cipher\LRPCipher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive LRP cipher tests based on Python reference implementation.
 *
 * Tests are based on:
 * - test_lrp.py
 * - test_lrp_cmac_vectors.py
 * - test_lrp_eval_vec.py
 * - test_lrp_sdm.py
 *
 * From: https://github.com/nfc-developer/sdm-backend
 *
 * @internal
 */
#[CoversClass(LRPCipher::class)]
class LRPTest extends TestCase
{
    /**
     * Test counter increment operation.
     */
    public function testIncrementCounter(): void
    {
        $reflection = new \ReflectionClass(LRPCipher::class);
        $method = $reflection->getMethod('incrementCounter');
        $method->setAccessible(true);

        // Test normal increment
        $counter = hex2bin('00000000000000000000000000000000');
        $result = $method->invoke(null, $counter);
        $this->assertIsString($result);
        $this->assertSame('00000000000000000000000000000001', bin2hex($result));

        // Test increment with carry
        $counter = hex2bin('000000000000000000000000000000FF');
        $result = $method->invoke(null, $counter);
        $this->assertIsString($result);
        $this->assertSame('00000000000000000000000000000100', bin2hex($result));

        // Test overflow
        $counter = hex2bin('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
        $result = $method->invoke(null, $counter);
        $this->assertIsString($result);
        $this->assertSame('00000000000000000000000000000000', bin2hex($result));
    }

    /**
     * Test nibble extraction from binary data.
     */
    public function testNibbles(): void
    {
        $reflection = new \ReflectionClass(LRPCipher::class);
        $method = $reflection->getMethod('getNibbles');
        $method->setAccessible(true);

        $data = hex2bin('12AB');
        $generator = $method->invoke(null, $data);
        $this->assertInstanceOf(\Generator::class, $generator);
        $nibbles = iterator_to_array($generator);

        $this->assertSame([1, 2, 10, 11], $nibbles);
    }

    /**
     * Test plaintext generation (Algorithm 1).
     */
    public function testGeneratePlaintexts(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $plaintexts = LRPCipher::generatePlaintexts($key);

        $this->assertCount(16, $plaintexts);
        $this->assertSame('B5CBF983BBE3C458189436288813EC30', strtoupper(bin2hex($plaintexts[0])));
        $this->assertSame('4EB06DF75D50712B5D20FA3700E04720', strtoupper(bin2hex($plaintexts[15])));
    }

    /**
     * Test updated key generation (Algorithm 2).
     */
    public function testGenerateUpdatedKeys(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);

        $this->assertCount(4, $updatedKeys);
        $this->assertSame('50A26CB5DF307E483DE532F6AFBEC27B', strtoupper(bin2hex($updatedKeys[0])));
        $this->assertSame('955C220F6F430E5E3E73BAF701242677', strtoupper(bin2hex($updatedKeys[2])));
    }

    /**
     * Test LRP evaluation (Algorithm 3) - Vector 1.
     */
    public function testEvalLrp1(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);

        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[0], hex2bin('00000000000000000000000000000000'), true);
        $this->assertSame('0A911DB37F0F25D6D589D13651AA5AB2', strtoupper(bin2hex($result)));
    }

    /**
     * Test LRP evaluation (Algorithm 3) - Vector 2.
     */
    public function testEvalLrp2(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);

        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[0], hex2bin('000102030405060708090A0B0C0D0E0F'), true);
        $this->assertSame('C33830341A78F36C6E14F859FB27547C', strtoupper(bin2hex($result)));
    }

    /**
     * Test LRP evaluation (Algorithm 3) - Vector 3.
     */
    public function testEvalLrp3(): void
    {
        $key = hex2bin('0F0E0D0C0B0A09080706050403020100');
        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);

        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[3], hex2bin('000102030405060708090A0B0C0D0E0F'), false);
        $this->assertSame('DE325199C4A9B8B999CDD8BD735D5B11', strtoupper(bin2hex($result)));
    }

    /**
     * Test LRICB encryption.
     */
    public function testLricbEnc(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $plaintext = hex2bin('000102030405060708090A0B0C0D0E0F');

        $cipher = new LRPCipher($key, 0, hex2bin('00000000000000000000000000000000'), true);
        $ciphertext = $cipher->encrypt($plaintext, $key, hex2bin('00000000000000000000000000000000'));

        $this->assertSame('E04BCADA1FD09A634908E505555777433D5759777FCC324ADDC56F4DAA34933D', strtoupper(bin2hex($ciphertext)));
    }

    /**
     * Test LRICB decryption.
     */
    public function testLricbDec(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $ciphertext = hex2bin('E04BCADA1FD09A634908E505555777433D5759777FCC324ADDC56F4DAA34933D');

        $cipher = new LRPCipher($key, 0, hex2bin('00000000000000000000000000000000'), true);
        $plaintext = $cipher->decrypt($ciphertext, $key, hex2bin('00000000000000000000000000000000'));

        $this->assertSame('000102030405060708090A0B0C0D0E0F', strtoupper(bin2hex($plaintext)));
    }

    /**
     * Test CMAC subkey derivation.
     */
    public function testCmacSubkeys(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        $k0 = LRPCipher::evalLRP($cipher->generatePlaintexts($key), $cipher->generateUpdatedKeys($key)[0], str_repeat("\x00", 16), true);

        // Test GF multiplication using reflection
        $reflection = new \ReflectionClass($cipher);
        $method = $reflection->getMethod('gfMultiply');
        $method->setAccessible(true);

        $k1 = $method->invoke($cipher, $k0, 2);
        $k2 = $method->invoke($cipher, $k0, 4);

        // Verify K1 and K2 are different and correct length
        $this->assertIsString($k1);
        $this->assertIsString($k2);
        $this->assertSame(16, strlen($k1));
        $this->assertSame(16, strlen($k2));
        $this->assertNotSame($k0, $k1);
        $this->assertNotSame($k1, $k2);
    }

    /**
     * Test CMAC generation - Vector 1 (empty message).
     */
    public function testCmacVec1(): void
    {
        $key = hex2bin('63A0169B4D9FE42C72B2784C806EAC21');
        $message = '';

        $cipher = new LRPCipher($key, 0);
        $mac = $cipher->cmac($message, $key);

        $this->assertSame('0E07C601970814A4176FDA633C6FC3DE', strtoupper(bin2hex($mac)));
    }

    /**
     * Test CMAC generation - Vector 2.
     */
    public function testCmacVec2(): void
    {
        $key = hex2bin('A6A9AF4B16215E0FF6F6E275931FF3E6');
        $message = hex2bin('54');

        $cipher = new LRPCipher($key, 0);
        $mac = $cipher->cmac($message, $key);

        $this->assertSame('165B3D44E8FB6B0334A1756E1F51C3F2', strtoupper(bin2hex($mac)));
    }

    /**
     * Test CMAC generation - Vector 3 (full block).
     */
    public function testCmacVec3(): void
    {
        $key = hex2bin('F4AD6ACAE230BE0DC1E909C5AD1D2045');
        $message = hex2bin('BE55F50AFF2D2FB46D1DEBB89A6E0831');

        $cipher = new LRPCipher($key, 0);
        $mac = $cipher->cmac($message, $key);

        $this->assertSame('CCFE4AA2EE60E19D4805E3B44641FC66', strtoupper(bin2hex($mac)));
    }

    /**
     * Test CMAC generation - Vector 4 (multiple blocks).
     */
    public function testCmacVec4(): void
    {
        $key = hex2bin('29C17CB0FB5FF67B1A5FD42EE630E2D4');
        $message = hex2bin('D59AF8AE586C3F38029F1D12C97CDB5CF49E26FF4A51C35CC9F51DEB1E5E2A0D');

        $cipher = new LRPCipher($key, 0);
        $mac = $cipher->cmac($message, $key);

        $this->assertSame('32A673683D5B7B3AEE0687AD9D7DFAC6', strtoupper(bin2hex($mac)));
    }

    /**
     * Test LRP eval vector 1 from AN12304.
     */
    public function testLrpEvalVec1(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $iv = hex2bin('');
        $finalize = false;
        $updatedKey = 0;
        $expected = hex2bin('50A26CB5DF307E483DE532F6AFBEC27B');

        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);
        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[$updatedKey], $iv, $finalize);

        $this->assertSame(strtoupper(bin2hex($expected)), strtoupper(bin2hex($result)));
    }

    /**
     * Test LRP eval vector 2 from AN12304.
     */
    public function testLrpEvalVec2(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $iv = hex2bin('');
        $finalize = true;
        $updatedKey = 0;
        $expected = hex2bin('1B330009B4D348B64C11D236B9DE064D');

        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);
        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[$updatedKey], $iv, $finalize);

        $this->assertSame(strtoupper(bin2hex($expected)), strtoupper(bin2hex($result)));
    }

    /**
     * Test LRP eval vector 10 from AN12304.
     */
    public function testLrpEvalVec10(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $iv = hex2bin('00000000000000000000000000000000');
        $finalize = true;
        $updatedKey = 0;
        $expected = hex2bin('0A911DB37F0F25D6D589D13651AA5AB2');

        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);
        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[$updatedKey], $iv, $finalize);

        $this->assertSame(strtoupper(bin2hex($expected)), strtoupper(bin2hex($result)));
    }

    /**
     * Test LRP eval vector 20 from AN12304.
     */
    public function testLrpEvalVec20(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $iv = hex2bin('000102030405060708090A0B0C0D0E0F');
        $finalize = true;
        $updatedKey = 0;
        $expected = hex2bin('C33830341A78F36C6E14F859FB27547C');

        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);
        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[$updatedKey], $iv, $finalize);

        $this->assertSame(strtoupper(bin2hex($expected)), strtoupper(bin2hex($result)));
    }

    /**
     * Test LRP eval vector 30 from AN12304.
     */
    public function testLrpEvalVec30(): void
    {
        $key = hex2bin('0F0E0D0C0B0A09080706050403020100');
        $iv = hex2bin('000102030405060708090A0B0C0D0E0F');
        $finalize = false;
        $updatedKey = 3;
        $expected = hex2bin('DE325199C4A9B8B999CDD8BD735D5B11');

        $plaintexts = LRPCipher::generatePlaintexts($key);
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);
        $result = LRPCipher::evalLRP($plaintexts, $updatedKeys[$updatedKey], $iv, $finalize);

        $this->assertSame(strtoupper(bin2hex($expected)), strtoupper(bin2hex($result)));
    }

    /**
     * Test XOR operation with different length strings throws exception.
     */
    public function testXorDifferentLengths(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        $reflection = new \ReflectionClass($cipher);
        $method = $reflection->getMethod('xorStrings');
        $method->setAccessible(true);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot XOR strings of different lengths');

        $method->invoke($cipher, 'short', 'longer string');
    }

    /**
     * Test invalid key length throws exception.
     */
    public function testInvalidKeyLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Key must be 16 bytes');

        new LRPCipher('short', 0);
    }

    /**
     * Test invalid update mode throws exception.
     */
    public function testInvalidUpdateMode(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Update mode must be between 0 and 3');

        new LRPCipher(str_repeat("\x00", 16), 5);
    }

    /**
     * Test encryption without padding requires block-aligned data.
     */
    public function testEncryptWithoutPaddingNonAligned(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0, null, false);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Data length must be a multiple of block size when padding is disabled');

        $cipher->encrypt('short', $key, str_repeat("\x00", 16));
    }

    /**
     * Test encryption with zero-length data throws exception.
     */
    public function testEncryptZeroLength(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0, null, false);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Zero length data is not supported');

        $cipher->encrypt('', $key, str_repeat("\x00", 16));
    }

    /**
     * Test invalid padding throws exception during decryption.
     */
    public function testInvalidPadding(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        // Encrypt data with padding
        $ciphertext = $cipher->encrypt('test', $key, str_repeat("\x00", 16));

        // Corrupt the ciphertext to create invalid padding
        $ciphertext[strlen($ciphertext) - 1] = "\xFF";

        // Create new cipher for decryption
        $cipher2 = new LRPCipher($key, 0, null, true);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid padding');

        $cipher2->decrypt($ciphertext, $key, str_repeat("\x00", 16));
    }

    /**
     * Test counter getter and setter.
     */
    public function testCounterGetterSetter(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        $counter = hex2bin('11111111111111111111111111111111');
        $cipher->setCounter($counter);

        $this->assertSame($counter, $cipher->getCounter());
    }

    /**
     * Test encryptECB method (interface implementation).
     */
    public function testEncryptECBMethod(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        $data = hex2bin('00000000000000000000000000000000');
        $result = $cipher->encryptECB($data, $key);

        $this->assertSame(16, strlen($result));
    }

    /**
     * Test gfMultiply with invalid factor.
     */
    public function testGfMultiplyInvalidFactor(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        $reflection = new \ReflectionClass($cipher);
        $method = $reflection->getMethod('gfMultiply');
        $method->setAccessible(true);

        $element = str_repeat("\x00", 16);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Factor must be 2 or 4');

        $method->invoke($cipher, $element, 3);
    }

    /**
     * Test constructor with empty counter.
     */
    public function testConstructorEmptyCounter(): void
    {
        $key = hex2bin('00000000000000000000000000000000');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Counter must not be empty');

        new LRPCipher($key, 0, '');
    }

    /**
     * Test setCounter with empty value.
     */
    public function testSetCounterEmpty(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Counter must not be empty');

        $cipher->setCounter('');
    }

    /**
     * Test variable-length counters (6 and 8 bytes as used in SDM).
     */
    public function testVariableLengthCounters(): void
    {
        $key = hex2bin('00000000000000000000000000000000');

        // 6-byte counter (as used in SDM for read counter)
        $cipher6 = new LRPCipher($key, 0, "\x00\x00\x00\x00\x00\x00");
        $this->assertSame(6, strlen($cipher6->getCounter()));

        // 8-byte counter (as used in SDM for PICC random)
        $cipher8 = new LRPCipher($key, 0, str_repeat("\x00", 8));
        $this->assertSame(8, strlen($cipher8->getCounter()));

        // Variable-length counter via setCounter
        $cipher = new LRPCipher($key, 0);
        $cipher->setCounter("\x01\x02\x03\x04");
        $this->assertSame(4, strlen($cipher->getCounter()));
    }
}
