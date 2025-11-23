<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\Cipher\AESCipher;
use KDuma\SDM\EncMode;
use KDuma\SDM\Exceptions\DecryptionException;
use KDuma\SDM\Exceptions\ValidationException;
use KDuma\SDM\ParamMode;
use KDuma\SDM\SDM;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Comprehensive test coverage for SDM implementation.
 *
 * @internal
 */
#[CoversClass(SDM::class)]
#[CoversClass(AESCipher::class)]
#[UsesClass(EncMode::class)]
#[UsesClass(ParamMode::class)]
#[UsesClass(DecryptionException::class)]
#[UsesClass(ValidationException::class)]
class SDMCoverageTest extends TestCase
{
    /**
     * Test getEncryptionMode detects LRP mode (24 bytes).
     */
    public function testGetEncryptionModeLRP(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $mode = $sdm->getEncryptionMode(str_repeat('x', 24));
        $this->assertSame(EncMode::LRP, $mode);
    }

    /**
     * Test getEncryptionMode throws exception for invalid length.
     */
    public function testGetEncryptionModeInvalid(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Unsupported encryption mode');

        $sdm->getEncryptionMode('invalid');
    }

    /**
     * Test calculateSdmmac with LRP mode throws exception.
     */
    public function testCalculateSdmmacLRPNotSupported(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('LRP mode is not supported');

        $sdm->calculateSdmmac(
            ParamMode::SEPARATED,
            hex2bin('00000000000000000000000000000000'),
            hex2bin('04DE5F1EACC040').hex2bin('3D0000'),
            mode: EncMode::LRP,
        );
    }

    /**
     * Test decryptFileData with LRP mode throws exception.
     */
    public function testDecryptFileDataLRPNotSupported(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('LRP mode is not supported');

        $sdm->decryptFileData(
            hex2bin('00000000000000000000000000000000'),
            hex2bin('04DE5F1EACC040').hex2bin('3D0000'),
            hex2bin('3D0000'),
            hex2bin('0000000000000000'),
            EncMode::LRP,
        );
    }

    /**
     * Test validatePlainSun with LRP mode throws exception.
     */
    public function testValidatePlainSunLRPNotSupported(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('LRP mode is not supported');

        $sdm->validatePlainSun(
            uid: hex2bin('041E3C8A2D6B80'),
            readCtr: hex2bin('000006'),
            sdmmac: hex2bin('4B00064004B0B3D3'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000'),
            mode: EncMode::LRP,
        );
    }

    /**
     * Test decryptSunMessage with LRP detected throws exception.
     */
    public function testDecryptSunMessageLRPNotSupported(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('LRP mode is not supported');

        $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('07D9CA2545881D4BFDD920BE1603268C0714420DD893A497'),
            sdmmac: hex2bin('F9481AC7D855BDB6'),
        );
    }

    /**
     * Test decryptSunMessage with unsupported UID length.
     */
    public function testDecryptSunMessageUnsupportedUIDLength(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Failed to decrypt PICCData - invalid encryption key or malformed data');

        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        // Create fake encrypted data with invalid UID length (not 0x07)
        // First byte after decryption should have UID length != 0x07
        $cipher = new AESCipher();
        $fakeData = "\xC5".str_repeat("\x00", 15); // 0xC5 = 11000101, UID length = 5
        $piccEncData = $cipher->encrypt($fakeData, hex2bin('00000000000000000000000000000000'), str_repeat("\x00", 16));

        $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: $piccEncData,
            sdmmac: hex2bin('0000000000000000'),
        );
    }

    /**
     * Test decryptSunMessage without UID mirroring throws exception.
     */
    public function testDecryptSunMessageNoUIDMirroring(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('UID cannot be null');

        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        // Create fake encrypted data without UID mirroring enabled
        // First byte should have bit 7 = 0 (no UID mirroring)
        $cipher = new AESCipher();
        $fakeData = "\x47".str_repeat("\x00", 15); // 0x47 = 01000111, UID length = 7, no UID mirroring
        $piccEncData = $cipher->encrypt($fakeData, hex2bin('00000000000000000000000000000000'), str_repeat("\x00", 16));

        $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: $piccEncData,
            sdmmac: hex2bin('0000000000000000'),
        );
    }

    /**
     * Test decryptSunMessage with enc file data but no read counter.
     * Note: MAC validation happens first, so we expect ValidationException.
     */
    public function testDecryptSunMessageFileDataNoReadCounter(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Message is not properly signed - invalid MAC');

        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        // Create fake encrypted data with UID mirroring but no read counter
        $cipher = new AESCipher();
        $fakeData = "\x87".hex2bin('04DE5F1EACC040').str_repeat("\x00", 8); // 0x87 = 10000111, UID mirroring enabled, read counter disabled
        $piccEncData = $cipher->encrypt($fakeData, hex2bin('00000000000000000000000000000000'), str_repeat("\x00", 16));

        $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: $piccEncData,
            sdmmac: hex2bin('0000000000000000'),
            encFileData: hex2bin('0000000000000000'),
        );
    }

    /**
     * Test calculateSdmmac with BULK mode without sdmmacParam.
     */
    public function testCalculateSdmmacBulkModeNoParam(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: '',
        );

        $mac = $sdm->calculateSdmmac(
            ParamMode::BULK,
            hex2bin('00000000000000000000000000000000'),
            hex2bin('04DE5F1EACC040').hex2bin('3D0000'),
            hex2bin('CEE9A53E3E463EF1'),
        );

        $this->assertSame(8, strlen($mac));
    }

    /**
     * Test calculateSdmmac with SEPARATED mode and sdmmacParam.
     */
    public function testCalculateSdmmacSeparatedModeWithParam(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: 'cmac',
        );

        $mac = $sdm->calculateSdmmac(
            ParamMode::SEPARATED,
            hex2bin('00000000000000000000000000000000'),
            hex2bin('04DE5F1EACC040').hex2bin('3D0000'),
            hex2bin('CEE9A53E3E463EF1'),
        );

        $this->assertSame(8, strlen($mac));
    }

    /**
     * Test calculateSdmmac without enc file data.
     */
    public function testCalculateSdmmacNoEncFileData(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $mac = $sdm->calculateSdmmac(
            ParamMode::SEPARATED,
            hex2bin('00000000000000000000000000000000'),
            hex2bin('04DE5F1EACC040').hex2bin('3D0000'),
        );

        $this->assertSame(8, strlen($mac));
    }

    /**
     * Test AESCipher XOR with different length strings throws exception.
     */
    public function testAESCipherXorDifferentLengths(): void
    {
        $cipher = new AESCipher();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot XOR strings of different lengths');

        // Use reflection to test private method
        $reflection = new \ReflectionClass($cipher);
        $method = $reflection->getMethod('xorStrings');
        $method->setAccessible(true);

        $method->invoke($cipher, 'short', 'longer string');
    }

    /**
     * Test validatePlainSun with successful validation.
     */
    public function testValidatePlainSunSuccess(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $result = $sdm->validatePlainSun(
            uid: hex2bin('041E3C8A2D6B80'),
            readCtr: hex2bin('000006'),
            sdmmac: hex2bin('4B00064004B0B3D3'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000'),
        );

        $this->assertArrayHasKey('encryption_mode', $result);
        $this->assertArrayHasKey('uid', $result);
        $this->assertArrayHasKey('read_ctr', $result);
        $this->assertSame(EncMode::AES, $result['encryption_mode']);
        $this->assertSame(hex2bin('041E3C8A2D6B80'), $result['uid']);
        $this->assertSame(6, $result['read_ctr']);
    }

    /**
     * Test AESCipher encryption/decryption failure.
     */
    public function testAESCipherEncryptionFailure(): void
    {
        $cipher = new AESCipher();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to encrypt data');

        // Invalid key length for AES-128 will cause failure
        $cipher->encrypt('test', 'short', str_repeat('i', 16));
    }

    /**
     * Test AESCipher decryption failure.
     */
    public function testAESCipherDecryptionFailure(): void
    {
        $cipher = new AESCipher();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to decrypt data');

        // Invalid key length for AES-128 will cause failure
        $cipher->decrypt('test', 'short', str_repeat('i', 16));
    }

    /**
     * Test AESCipher ECB encryption failure.
     */
    public function testAESCipherECBEncryptionFailure(): void
    {
        $cipher = new AESCipher();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Failed to encrypt data in ECB mode');

        // Invalid key length for AES-128 will cause failure
        $cipher->encryptECB('test', 'short');
    }

    /**
     * Test that decryptFileData successfully decrypts file data.
     */
    public function testDecryptFileDataSuccess(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $result = $sdm->decryptFileData(
            sdmFileReadKey: hex2bin('00000000000000000000000000000000'),
            piccData: hex2bin('04958CAA5C5E80').hex2bin('080000'),
            readCtr: hex2bin('080000'),
            encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962'),
        );

        $this->assertSame(16, strlen($result));
    }
}
