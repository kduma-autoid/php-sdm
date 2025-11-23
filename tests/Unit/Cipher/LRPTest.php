<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\Cipher;

use KDuma\SDM\Cipher\LRPCipher;
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
 *
 * @coversNothing
 */
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
        $this->assertSame('C6A13B37878F5B826F4F8162A1C8D879', strtoupper(bin2hex($plaintexts[0])));
        $this->assertSame('55BFE6B5ABC5CA5DE45D1E213D259F5C', strtoupper(bin2hex($plaintexts[15])));
    }

    /**
     * Test updated key generation (Algorithm 2).
     */
    public function testGenerateUpdatedKeys(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $updatedKeys = LRPCipher::generateUpdatedKeys($key);

        $this->assertCount(4, $updatedKeys);
        $this->assertSame('EBA0B0A857D6EBA7E7F25E9EAF6CB697', strtoupper(bin2hex($updatedKeys[0])));
        $this->assertSame('B52D9EA628EEF96D8BEB0D0F8468C4C0', strtoupper(bin2hex($updatedKeys[2])));
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
        $this->assertSame('C01088377F21CDEB0493F622494042E9', strtoupper(bin2hex($result)));
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
        $this->assertSame('47C8C37794AFE68128EA850780583C68', strtoupper(bin2hex($result)));
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
        $this->assertSame('3AFDFF318D651C26709367337EE43F21', strtoupper(bin2hex($result)));
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

        $this->assertSame('5A0D36F43C5BCF66DE377A75C4F878ABB4DF7CE9F07942C7D58FB7579BF7CD68', strtoupper(bin2hex($ciphertext)));
    }

    /**
     * Test LRICB decryption.
     */
    public function testLricbDec(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $ciphertext = hex2bin('5A0D36F43C5BCF66DE377A75C4F878ABB4DF7CE9F07942C7D58FB7579BF7CD68');

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

        $this->assertSame('60B35BF3FE76C3DA29EE0AEDD3D87EBF', strtoupper(bin2hex($mac)));
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

        $this->assertSame('C24F9E2CC59D63918D69BFB4B6A8AFD5', strtoupper(bin2hex($mac)));
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

        $this->assertSame('D47AC06A1D47E7F37E67DAC03255B5C2', strtoupper(bin2hex($mac)));
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
        $expected = hex2bin('EBA0B0A857D6EBA7E7F25E9EAF6CB697');

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
        $expected = hex2bin('8D2716F3027BC199F3EFD6AAD772F847');

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
        $expected = hex2bin('C01088377F21CDEB0493F622494042E9');

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
        $expected = hex2bin('47C8C37794AFE68128EA850780583C68');

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
        $expected = hex2bin('3AFDFF318D651C26709367337EE43F21');

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
     * Test invalid counter length throws exception.
     */
    public function testInvalidCounterLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Counter must be 16 bytes');

        new LRPCipher(str_repeat("\x00", 16), 0, 'short');
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
     * Test set counter with invalid length throws exception.
     */
    public function testSetCounterInvalidLength(): void
    {
        $key = hex2bin('00000000000000000000000000000000');
        $cipher = new LRPCipher($key, 0);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Counter must be 16 bytes');

        $cipher->setCounter('short');
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
}
