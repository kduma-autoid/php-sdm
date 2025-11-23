<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\EncMode;
use KDuma\SDM\Exceptions\ValidationException;
use KDuma\SDM\KeyDerivation;
use KDuma\SDM\ParamMode;
use KDuma\SDM\SDM;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * This code was implemented based on the examples provided in:
 * - AN12196: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints
 *
 * Tests are based on the Python implementation at:
 * https://github.com/nfc-developer/sdm-backend/blob/master/tests/test_libsdm.py
 *
 * @internal
 */
#[CoversNothing]
class SDMProtocolTest extends TestCase
{
    /**
     * Test from AN12196 page 12
     * https://ntag.nxp.com/424?e=EF963FF7828658A599F3041510671E88&c=94EED9EE65337086.
     */
    public function testSun1(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $res = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('EF963FF7828658A599F3041510671E88'),
            sdmmac: hex2bin('94EED9EE65337086'),
        );

        $this->assertSame("\xc7", $res['picc_data_tag']);
        $this->assertSame(hex2bin('04DE5F1EACC040'), $res['uid']);
        $this->assertSame(61, $res['read_ctr']);
        $this->assertNull($res['file_data']);
        $this->assertSame(EncMode::AES, $res['encryption_mode']);
    }

    /**
     * Test from AN12196 page 18
     * https://www.my424dna.com/?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6.
     */
    public function testSun2(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: 'cmac',
        );

        $res = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('FD91EC264309878BE6345CBE53BADF40'),
            sdmmac: hex2bin('ECC1E7F6C6C73BF6'),
            encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962'),
        );

        $this->assertSame("\xc7", $res['picc_data_tag']);
        $this->assertSame(hex2bin('04958CAA5C5E80'), $res['uid']);
        $this->assertSame(8, $res['read_ctr']);
        $this->assertSame('xxxxxxxxxxxxxxxx', $res['file_data']);
        $this->assertSame(EncMode::AES, $res['encryption_mode']);
    }

    /**
     * Test with custom diversified keys (not factory default zeros).
     */
    public function testSun3Custom(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('42aff114f2cb3b6141be6dc95dfc5416'),
            macKey: hex2bin('b62a9baf092439bd43c62aee96b970c5'),
        );

        $res = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('42aff114f2cb3b6141be6dc95dfc5416'),
            sdmFileReadKey: fn ($uid) => hex2bin('b62a9baf092439bd43c62aee96b970c5'),
            piccEncData: hex2bin('8ACADDEF0A9B62CDAE39A16B83FC14DE'),
            sdmmac: hex2bin('238B2543A8DEBAD8'),
            encFileData: hex2bin('B8436E11F627BB7F543FCC0C1E0D1A89'),
        );

        $this->assertSame("\xc7", $res['picc_data_tag']);
        $this->assertSame(hex2bin('041d3c8a2d6b80'), $res['uid']);
        $this->assertSame(291, $res['read_ctr']);
        $this->assertSame(hex2bin('4e545858716e6f5f6f42467077792d56'), $res['file_data']);
        $this->assertSame(EncMode::AES, $res['encryption_mode']);
    }

    /**
     * Test that wrong SDMMAC throws exception.
     */
    public function testSun2WrongSdmmac(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Message is not properly signed - invalid MAC');

        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
            sdmmacParam: 'cmac',
        );

        $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('FD91EC264309878BE6345CBE53BADF40'),
            sdmmac: hex2bin('3CC1E7F6C6C33B33'),
            encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962'),
        );
    }

    /**
     * Test plain SDM validation (no encryption, only MAC).
     */
    public function testPlainSdm(): void
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
        $this->assertSame(hex2bin('041E3C8A2D6B80'), $result['uid']);
        $this->assertSame(6, $result['read_ctr']);
    }

    /**
     * Test plain SDM with wrong MAC throws exception.
     */
    public function testPlainSdmWrong(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('Message is not properly signed - invalid MAC');

        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $sdm->validatePlainSun(
            uid: hex2bin('041E3C8A2D6B80'),
            readCtr: hex2bin('000006'),
            sdmmac: hex2bin('AB00064004B0B3AB'),
            sdmFileReadKey: hex2bin('00000000000000000000000000000000'),
            mode: EncMode::AES,
        );
    }

    /**
     * Test decryption with key derivation function (KDF) - test 1.
     */
    public function testDecryptWithKdf1(): void
    {
        $masterKey = hex2bin('47BBB68AFA73F31310BEEFCE5DDA692DBAD671A03FEAD5A9BBDBCF3CD6D4C521');
        $kdf = new KeyDerivation();

        $sdm = new SDM(
            encKey: $kdf->deriveUndiversifiedKey($masterKey, 1),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $res = $sdm->decryptSunMessage(
            paramMode: ParamMode::BULK,
            sdmMetaReadKey: $kdf->deriveUndiversifiedKey($masterKey, 1),
            sdmFileReadKey: fn ($uid) => $kdf->deriveTagKey($masterKey, $uid, 2),
            piccEncData: hex2bin('8DE9030262807261850FCCF5FE007E21'),
            encFileData: hex2bin('382B4C3D68552C3A5F417F0695A3D857923764E1737AD1F80E834E46387F45DC77FE7468BBCF9DBF43B29CA58E8D6435F908C9C0CD56E9B4B9960FE1279C5DF1'),
            sdmmac: hex2bin('DF3EF20BE7D91C8E'),
        );

        $this->assertSame("\xc7", $res['picc_data_tag']);
        $this->assertSame(hex2bin('04c24eda926980'), $res['uid']);
        $this->assertSame(1, $res['read_ctr']);
        $this->assertSame('NT1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEEEEEEEEEEEE', $res['file_data']);
        $this->assertSame(EncMode::AES, $res['encryption_mode']);
    }

    /**
     * Test decryption with key derivation function (KDF) - test 2.
     */
    public function testDecryptWithKdf2(): void
    {
        $masterKey = hex2bin('47BBB68AFA73F31310BEEFCE5DDA692DBAD671A03FEAD5A9BBDBCF3CD6D4C521');
        $kdf = new KeyDerivation();

        $sdm = new SDM(
            encKey: $kdf->deriveUndiversifiedKey($masterKey, 1),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $res = $sdm->decryptSunMessage(
            paramMode: ParamMode::BULK,
            sdmMetaReadKey: $kdf->deriveUndiversifiedKey($masterKey, 1),
            sdmFileReadKey: fn ($uid) => $kdf->deriveTagKey($masterKey, $uid, 2),
            piccEncData: hex2bin('4F5B914723915D456C038FE658686CD5'),
            encFileData: hex2bin('5CE7DCDEA93F5DA7AAA0AADC97485ABF'),
            sdmmac: hex2bin('FFCD8DE82AD05289'),
        );

        $this->assertSame("\xc7", $res['picc_data_tag']);
        $this->assertSame(hex2bin('047d5f2aaa6180'), $res['uid']);
        $this->assertSame(2, $res['read_ctr']);
        $this->assertSame("CC\x04aaaaEEEEEEEEE", $res['file_data']);
        $this->assertSame(EncMode::AES, $res['encryption_mode']);
    }

    /**
     * Test LRP mode with encrypted file data - from test_lrp_sdm.py.
     */
    public function testSdmLrp1(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $res = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('65628ED36888CF9C84797E43ECACF114C6ED9A5E101EB592'),
            encFileData: hex2bin('4ADE304B5AB9474CB40AFFCAB0607A85'),
            sdmmac: hex2bin('759B10964491D74A'),
        );

        $this->assertSame("\xc7", $res['picc_data_tag']);
        $this->assertSame(hex2bin('042e1d222a6380'), $res['uid']);
        $this->assertSame(123, $res['read_ctr']);
        $this->assertSame('0102030400000000', $res['file_data']);
        $this->assertSame(EncMode::LRP, $res['encryption_mode']);
    }

    /**
     * Test LRP mode without encrypted file data - from test_lrp_sdm.py.
     */
    public function testSdmLrp2(): void
    {
        $sdm = new SDM(
            encKey: hex2bin('00000000000000000000000000000000'),
            macKey: hex2bin('00000000000000000000000000000000'),
        );

        $res = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: hex2bin('00000000000000000000000000000000'),
            sdmFileReadKey: fn ($uid) => hex2bin('00000000000000000000000000000000'),
            piccEncData: hex2bin('AAE1508939ECF6FF26BCE407959AB1A5EC022819A35CD293'),
            sdmmac: hex2bin('D50F353E30FDE644'),
        );

        $this->assertSame("\xc7", $res['picc_data_tag']);
        $this->assertSame(hex2bin('042e1d222a6380'), $res['uid']);
        $this->assertSame(106, $res['read_ctr']);
        $this->assertNull($res['file_data']);
        $this->assertSame(EncMode::LRP, $res['encryption_mode']);
    }
}
