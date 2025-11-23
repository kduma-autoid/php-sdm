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
 * @internal
 */
#[CoversClass(SDM::class)]
#[UsesClass(AESCipher::class)]
#[UsesClass(EncMode::class)]
#[UsesClass(ParamMode::class)]
#[UsesClass(DecryptionException::class)]
#[UsesClass(ValidationException::class)]
final class SDMTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $sdm = new SDM('1234567890123456', '1234567890123456');

        $this->assertInstanceOf(SDM::class, $sdm);
    }

    /**
     * Test decrypt method with invalid data throws DecryptionException.
     */
    public function testDecryptInvalidData(): void
    {
        $sdm = new SDM(str_repeat('k', 16), str_repeat('m', 16));

        $this->expectException(DecryptionException::class);

        $sdm->decrypt('invalid', 'encFileData', 'cmac1234');
    }

    /**
     * Test validate method returns false for invalid MAC.
     */
    public function testValidateInvalidMac(): void
    {
        $sdm = new SDM(str_repeat('k', 16), str_repeat('m', 16));

        $result = $sdm->validate(str_repeat('d', 10), 'badmac12');

        $this->assertFalse($result);
    }
}
