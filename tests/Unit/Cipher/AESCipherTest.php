<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\Cipher;

use KDuma\SDM\Cipher\AESCipher;
use PHPUnit\Framework\TestCase;

class AESCipherTest extends TestCase
{
    public function test_can_be_instantiated(): void
    {
        $cipher = new AESCipher();

        $this->assertInstanceOf(AESCipher::class, $cipher);
    }

    // TODO: Add more tests
}
