<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests;

use KDuma\SDM\SDMMessage;
use KDuma\SDM\Exceptions\InvalidMessageException;

/**
 * Tests for SDMMessage class.
 */
class SDMMessageTest extends SDMTestCase
{
    public function testConstructor(): void
    {
        $message = new SDMMessage(
            piccData: 'test_picc',
            encryptedData: 'test_encrypted',
            cmac: 'test_cmac'
        );

        $this->assertInstanceOf(SDMMessage::class, $message);
        $this->assertEquals('test_picc', $message->getPiccData());
        $this->assertEquals('test_encrypted', $message->getEncryptedData());
        $this->assertEquals('test_cmac', $message->getCmac());
    }

    public function testFromUrlThrowsException(): void
    {
        $this->expectException(InvalidMessageException::class);
        SDMMessage::fromUrl('https://example.com/tag?picc_data=test');
    }

    public function testFromArrayThrowsException(): void
    {
        $this->expectException(InvalidMessageException::class);
        SDMMessage::fromArray([
            'picc_data' => 'test',
            'enc' => 'test',
            'cmac' => 'test'
        ]);
    }
}
