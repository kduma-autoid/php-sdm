<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\PICC;

use KDuma\SDM\PICC\PICCData;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(PICCData::class)]
final class PICCDataTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $piccData = new PICCData('0123456', 42);

        $this->assertInstanceOf(PICCData::class, $piccData);
    }

    public function testGetUid(): void
    {
        $uid = hex2bin('04DE5F1EACC040');
        $piccData = new PICCData($uid, 100);

        $this->assertSame($uid, $piccData->getUid());
    }

    public function testGetReadCounter(): void
    {
        $piccData = new PICCData('test_uid', 123);

        $this->assertSame(123, $piccData->getReadCounter());
    }

    public function testFromEncryptedNotImplemented(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Not implemented yet');

        PICCData::fromEncrypted('encrypted_data');
    }
}
