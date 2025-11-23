<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\SUN;

use KDuma\SDM\SUN\SUNMessage;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(SUNMessage::class)]
final class SUNMessageTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $message = new SUNMessage('enc_picc', 'enc_file', 'cmac');

        $this->assertInstanceOf(SUNMessage::class, $message);
    }

    public function testGetEncPICCData(): void
    {
        $encPICCData = hex2bin('EF963FF7828658A599F3041510671E88');
        $message = new SUNMessage($encPICCData, 'enc_file', 'cmac');

        $this->assertSame($encPICCData, $message->getEncPICCData());
    }

    public function testGetEncFileData(): void
    {
        $encFileData = hex2bin('CEE9A53E3E463EF1F459635736738962');
        $message = new SUNMessage('enc_picc', $encFileData, 'cmac');

        $this->assertSame($encFileData, $message->getEncFileData());
    }

    public function testGetCmac(): void
    {
        $cmac = hex2bin('94EED9EE65337086');
        $message = new SUNMessage('enc_picc', 'enc_file', $cmac);

        $this->assertSame($cmac, $message->getCmac());
    }

    public function testFromUrlParamsNotImplemented(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Not implemented yet');

        SUNMessage::fromUrlParams(['picc_data' => 'test']);
    }
}
