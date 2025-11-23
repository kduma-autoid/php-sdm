<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\Cipher\AESCipher;
use KDuma\SDM\Cipher\LRPCipher;
use KDuma\SDM\Enums\EncryptionMode;
use KDuma\SDM\Enums\ParameterMode;
use KDuma\SDM\Exceptions\ValidationException;
use KDuma\SDM\KeyDerivation\KeyDerivation;
use KDuma\SDM\SDMDecryptor;
use PHPUnit\Framework\TestCase;

/**
 * Tests based on https://github.com/nfc-developer/sdm-backend/raw/refs/heads/master/tests/test_libsdm.py
 *
 * This code was implemented based on the examples provided in:
 * AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
 */
class SDMDecryptionTest extends TestCase
{
    /**
     * Test basic SUN decryption with separated parameters
     * From AN12196 page 12
     * https://ntag.nxp.com/424?e=EF963FF7828658A599F3041510671E88&c=94EED9EE65337086
     */
    public function test_sun1_basic_decryption(): void
    {
        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000')
        );

        $result = $decryptor->decrypt(
            piccEncData: hex2bin('EF963FF7828658A599F3041510671E88'),
            sdmmac: hex2bin('94EED9EE65337086')
        );

        $this->assertEquals("\xc7", $result->piccDataTag);
        $this->assertEquals(hex2bin('04de5f1eacc040'), $result->uid);
        $this->assertEquals(61, $result->readCounter);
        $this->assertNull($result->fileData);
        $this->assertEquals(EncryptionMode::AES, $result->encryptionMode);
    }

    /**
     * Test SUN decryption with file data encryption
     * FROM AN12196 page 18
     * https://www.my424dna.com/?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6
     */
    public function test_sun2_with_file_data(): void
    {
        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000')
        );

        $result = $decryptor->decrypt(
            piccEncData: hex2bin('FD91EC264309878BE6345CBE53BADF40'),
            sdmmac: hex2bin('ECC1E7F6C6C73BF6'),
            encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962')
        );

        $this->assertEquals("\xc7", $result->piccDataTag);
        $this->assertEquals(hex2bin('04958caa5c5e80'), $result->uid);
        $this->assertEquals(8, $result->readCounter);
        $this->assertEquals('xxxxxxxxxxxxxxxx', $result->fileData);
        $this->assertEquals(EncryptionMode::AES, $result->encryptionMode);
    }

    /**
     * Test SUN decryption with custom-derived keys
     */
    public function test_sun3_custom_keys(): void
    {
        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::SEPARATED,
            sdmMetaReadKey: hex2bin('42aff114f2cb3b6141be6dc95dfc5416'),
            sdmFileReadKey: hex2bin('b62a9baf092439bd43c62aee96b970c5'),
            sdmmacParam: '' // Empty SDMMAC param (no separator added)
        );

        $result = $decryptor->decrypt(
            piccEncData: hex2bin('8ACADDEF0A9B62CDAE39A16B83FC14DE'),
            sdmmac: hex2bin('238B2543A8DEBAD8'),
            encFileData: hex2bin('B8436E11F627BB7F543FCC0C1E0D1A89')
        );

        $this->assertEquals("\xc7", $result->piccDataTag);
        $this->assertEquals(hex2bin('041d3c8a2d6b80'), $result->uid);
        $this->assertEquals(291, $result->readCounter);
        $this->assertEquals(hex2bin('4e545858716e6f5f6f42467077792d56'), $result->fileData);
        $this->assertEquals(EncryptionMode::AES, $result->encryptionMode);
    }

    /**
     * Test that invalid SDMMAC throws ValidationException
     */
    public function test_sun2_wrong_sdmmac_throws_exception(): void
    {
        $this->expectException(ValidationException::class);

        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000')
        );

        $decryptor->decrypt(
            piccEncData: hex2bin('FD91EC264309878BE6345CBE53BADF40'),
            sdmmac: hex2bin('3CC1E7F6C6C33B33'), // Wrong SDMMAC
            encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962')
        );
    }

    /**
     * Test plain SUN validation (no encryption, only MAC)
     */
    public function test_plain_sdm_validation(): void
    {
        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::PLAIN,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000')
        );

        $result = $decryptor->validatePlainSUN(
            uid: hex2bin('041E3C8A2D6B80'),
            readCounter: hex2bin('000006'),
            sdmmac: hex2bin('4B00064004B0B3D3'),
            encryptionMode: EncryptionMode::AES
        );

        $this->assertTrue($result);
    }

    /**
     * Test plain SUN validation with wrong SDMMAC throws exception
     */
    public function test_plain_sdm_wrong_throws_exception(): void
    {
        $this->expectException(ValidationException::class);

        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::PLAIN,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000')
        );

        $decryptor->validatePlainSUN(
            uid: hex2bin('041E3C8A2D6B80'),
            readCounter: hex2bin('000006'),
            sdmmac: hex2bin('AB00064004B0B3AB'), // Wrong SDMMAC
            encryptionMode: EncryptionMode::AES
        );
    }

    /**
     * Test LRP encryption mode with file data
     *
     * @group lrp
     */
    public function test_sdm_lrp1_with_file_data(): void
    {
        $this->markTestSkipped('LRP encryption mode is not yet implemented');
        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000')
        );

        $result = $decryptor->decrypt(
            piccEncData: hex2bin('07D9CA2545881D4BFDD920BE1603268C0714420DD893A497'),
            encFileData: hex2bin('D6E921C47DB4C17C56F979F81559BB83'),
            sdmmac: hex2bin('F9481AC7D855BDB6')
        );

        $this->assertEquals("\xc7", $result->piccDataTag);
        $this->assertEquals(hex2bin('049b112a2f7080'), $result->uid);
        $this->assertEquals(4, $result->readCounter);
        $this->assertEquals('NTXXb7dz3PsYYBlU', $result->fileData);
        $this->assertEquals(EncryptionMode::LRP, $result->encryptionMode);
    }

    /**
     * Test LRP encryption mode without file data
     *
     * @group lrp
     */
    public function test_sdm_lrp2_without_file_data(): void
    {
        $this->markTestSkipped('LRP encryption mode is not yet implemented');
        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000')
        );

        $result = $decryptor->decrypt(
            piccEncData: hex2bin('1FCBE61B3E4CAD980CBFDD333E7A4AC4A579569BAFD22C5F'),
            sdmmac: hex2bin('4231608BA7B02BA9')
        );

        $this->assertEquals("\xc7", $result->piccDataTag);
        $this->assertEquals(hex2bin('04940e2a2f7080'), $result->uid);
        $this->assertEquals(3, $result->readCounter);
        $this->assertNull($result->fileData);
        $this->assertEquals(EncryptionMode::LRP, $result->encryptionMode);
    }

    /**
     * Test decryption with key derivation function (KDF) - Test case 1
     * Tests bulk mode with master key derivation for multiple tags
     */
    public function test_decrypt_with_kdf1(): void
    {
        $masterKey = hex2bin('47BBB68AFA73F31310BEEFCE5DDA692DBAD671A03FEAD5A9BBDBCF3CD6D4C521');

        $keyDerivation = new KeyDerivation($masterKey);

        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::BULK,
            sdmMetaReadKey: $keyDerivation->deriveUndiversifiedKey(1),
            sdmFileReadKeyDerivation: $keyDerivation,
            sdmFileReadKeyNumber: 2
        );

        $result = $decryptor->decrypt(
            piccEncData: hex2bin('8DE9030262807261850FCCF5FE007E21'),
            encFileData: hex2bin('382B4C3D68552C3A5F417F0695A3D857923764E1737AD1F80E834E46387F45DC77FE7468BBCF9DBF43B29CA58E8D6435F908C9C0CD56E9B4B9960FE1279C5DF1'),
            sdmmac: hex2bin('DF3EF20BE7D91C8E')
        );

        $this->assertEquals("\xc7", $result->piccDataTag);
        $this->assertEquals(hex2bin('04c24eda926980'), $result->uid);
        $this->assertEquals(1, $result->readCounter);
        $this->assertEquals('NT1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEEEEEEEEEEEE', $result->fileData);
        $this->assertEquals(EncryptionMode::AES, $result->encryptionMode);
    }

    /**
     * Test decryption with key derivation function (KDF) - Test case 2
     * Tests bulk mode with master key derivation for multiple tags
     */
    public function test_decrypt_with_kdf2(): void
    {
        $masterKey = hex2bin('47BBB68AFA73F31310BEEFCE5DDA692DBAD671A03FEAD5A9BBDBCF3CD6D4C521');

        $keyDerivation = new KeyDerivation($masterKey);

        $decryptor = new SDMDecryptor(
            parameterMode: ParameterMode::BULK,
            sdmMetaReadKey: $keyDerivation->deriveUndiversifiedKey(1),
            sdmFileReadKeyDerivation: $keyDerivation,
            sdmFileReadKeyNumber: 2
        );

        $result = $decryptor->decrypt(
            piccEncData: hex2bin('4F5B914723915D456C038FE658686CD5'),
            encFileData: hex2bin('5CE7DCDEA93F5DA7AAA0AADC97485ABF'),
            sdmmac: hex2bin('FFCD8DE82AD05289')
        );

        $this->assertEquals("\xc7", $result->piccDataTag);
        $this->assertEquals(hex2bin('047d5f2aaa6180'), $result->uid);
        $this->assertEquals(2, $result->readCounter);
        $this->assertEquals("CC\x04aaaaEEEEEEEEE", $result->fileData);
        $this->assertEquals(EncryptionMode::AES, $result->encryptionMode);
    }
}
