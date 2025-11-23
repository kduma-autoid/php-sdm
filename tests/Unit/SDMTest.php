<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\SDM;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(SDM::class)]
final class SDMTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $sdm = new SDM('1234567890123456', '1234567890123456');

        $this->assertInstanceOf(SDM::class, $sdm);
    }

    /**
     * Test that decrypt method throws RuntimeException (not yet implemented).
     */
    public function testDecryptNotImplemented(): void
    {
        $sdm = new SDM('1234567890123456', '1234567890123456');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Not implemented yet');

        $sdm->decrypt('encData', 'encFileData', 'cmac');
    }

    /**
     * Test that validate method throws RuntimeException (not yet implemented).
     */
    public function testValidateNotImplemented(): void
    {
        $sdm = new SDM('1234567890123456', '1234567890123456');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Not implemented yet');

        $sdm->validate('data', 'cmac');
    }
}
