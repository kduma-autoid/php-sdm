<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit\Cipher;

use KDuma\SDM\Cipher\AESCipher;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class AESCipherTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $cipher = new AESCipher();

        $this->assertInstanceOf(AESCipher::class, $cipher);
    }

    // TODO: Add more tests
}
