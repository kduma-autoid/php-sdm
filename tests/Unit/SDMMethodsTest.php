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
 * Comprehensive method coverage tests for SDM class.
 *
 * @internal
 */
#[CoversClass(SDM::class)]
#[UsesClass(AESCipher::class)]
#[UsesClass(EncMode::class)]
#[UsesClass(ParamMode::class)]
#[UsesClass(DecryptionException::class)]
#[UsesClass(ValidationException::class)]
final class SDMMethodsTest extends TestCase
{
    /**
     * Test calculateSdmmac with default AES mode.
     */
    public function testCalculateSdmmacDefaultMode(): void
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
     * Test calculateSdmmac with explicit AES mode.
     */
    public function testCalculateSdmmacExplicitAESMode(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $mac = $sdm->calculateSdmmac(
            ParamMode::SEPARATED,
            hex2bin('00000000000000000000000000000000'),
            hex2bin('04DE5F1EACC040').hex2bin('3D0000'),
            mode: EncMode::AES,
        );

        $this->assertSame(8, strlen($mac));
    }

    /**
     * Test decryptFileData with default mode.
     */
    public function testDecryptFileDataDefaultMode(): void
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

    /**
     * Test decryptFileData with explicit AES mode.
     */
    public function testDecryptFileDataExplicitAESMode(): void
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
            mode: EncMode::AES,
        );

        $this->assertSame(16, strlen($result));
    }

    /**
     * Test validatePlainSun with default mode.
     */
    public function testValidatePlainSunDefaultMode(): void
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

        $this->assertIsArray($result);
        $this->assertArrayHasKey('encryption_mode', $result);
        $this->assertArrayHasKey('uid', $result);
        $this->assertArrayHasKey('read_ctr', $result);
    }

    /**
     * Test validatePlainSun with explicit AES mode.
     */
    public function testValidatePlainSunExplicitAESMode(): void
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
            mode: EncMode::AES,
        );

        $this->assertSame(EncMode::AES, $result['encryption_mode']);
    }

    /**
     * Test getEncryptionMode with AES (16 bytes).
     */
    public function testGetEncryptionModeAES(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $mode = $sdm->getEncryptionMode(hex2bin('EF963FF7828658A599F3041510671E88'));

        $this->assertSame(EncMode::AES, $mode);
    }

    /**
     * Test decrypt method wrapper.
     */
    public function testDecryptWrapper(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: 'cmac',
        );

        $result = $sdm->decrypt(
            hex2bin('FD91EC264309878BE6345CBE53BADF40'),
            hex2bin('CEE9A53E3E463EF1F459635736738962'),
            hex2bin('ECC1E7F6C6C73BF6'),
        );

        $this->assertIsArray($result);
        $this->assertArrayHasKey('picc_data_tag', $result);
        $this->assertArrayHasKey('uid', $result);
        $this->assertArrayHasKey('read_ctr', $result);
        $this->assertArrayHasKey('file_data', $result);
        $this->assertArrayHasKey('encryption_mode', $result);
    }

    /**
     * Test validate method wrapper returns true for valid MAC.
     */
    public function testValidateWrapperValid(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $result = $sdm->validate(
            hex2bin('041E3C8A2D6B80').hex2bin('000006'),
            hex2bin('4B00064004B0B3D3'),
        );

        $this->assertTrue($result);
    }

    /**
     * Test decryptSunMessage without encrypted file data.
     */
    public function testDecryptSunMessageNoFileData(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $result = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('EF963FF7828658A599F3041510671E88'),
            sdmmac: hex2bin('94EED9EE65337086'),
        );

        $this->assertNull($result['file_data']);
    }

    /**
     * Test decryptSunMessage with encrypted file data.
     */
    public function testDecryptSunMessageWithFileData(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: 'cmac',
        );

        $result = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('FD91EC264309878BE6345CBE53BADF40'),
            sdmmac: hex2bin('ECC1E7F6C6C73BF6'),
            encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962'),
        );

        $this->assertNotNull($result['file_data']);
        $this->assertSame('xxxxxxxxxxxxxxxx', $result['file_data']);
    }

    /**
     * Test calculateSdmmac with BULK mode and no sdmmacParam.
     */
    public function testCalculateSdmmacBulkModeEmptyParam(): void
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
     * Test calculateSdmmac with SEPARATED mode and sdmmacParam set.
     */
    public function testCalculateSdmmacSeparatedModeWithCustomParam(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: 'mac',
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
     * Test decryptSunMessage with BULK parameter mode.
     */
    public function testDecryptSunMessageBulkMode(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $result = $sdm->decryptSunMessage(
            paramMode: ParamMode::BULK,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('EF963FF7828658A599F3041510671E88'),
            sdmmac: hex2bin('94EED9EE65337086'),
        );

        $this->assertIsArray($result);
        $this->assertSame(EncMode::AES, $result['encryption_mode']);
    }

    /**
     * Test constructor with custom sdmmacParam.
     */
    public function testConstructorWithCustomParam(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: 'custom',
        );

        $this->assertInstanceOf(SDM::class, $sdm);
    }

    /**
     * Test decryptSunMessage returns correct structure.
     */
    public function testDecryptSunMessageStructure(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $result = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('EF963FF7828658A599F3041510671E88'),
            sdmmac: hex2bin('94EED9EE65337086'),
        );

        $this->assertArrayHasKey('picc_data_tag', $result);
        $this->assertArrayHasKey('uid', $result);
        $this->assertArrayHasKey('read_ctr', $result);
        $this->assertArrayHasKey('file_data', $result);
        $this->assertArrayHasKey('encryption_mode', $result);
        $this->assertIsString($result['picc_data_tag']);
        $this->assertIsString($result['uid']);
        $this->assertIsInt($result['read_ctr']);
        $this->assertSame(EncMode::AES, $result['encryption_mode']);
    }

    /**
     * Test validatePlainSun returns correct structure.
     */
    public function testValidatePlainSunStructure(): void
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
        $this->assertIsString($result['uid']);
        $this->assertIsInt($result['read_ctr']);
    }
}
