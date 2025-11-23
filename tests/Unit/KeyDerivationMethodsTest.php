<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\Cipher\AESCipher;
use KDuma\SDM\KeyDerivation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;

/**
 * Additional method coverage tests for KeyDerivation class.
 *
 * @internal
 */
#[CoversClass(KeyDerivation::class)]
#[UsesClass(AESCipher::class)]
final class KeyDerivationMethodsTest extends TestCase
{
    /**
     * Test constructor creates instance.
     */
    public function testConstructor(): void
    {
        $kdf = new KeyDerivation();

        $this->assertInstanceOf(KeyDerivation::class, $kdf);
    }

    /**
     * Test deriveUndiversifiedKey with 32-byte master key.
     */
    public function testDeriveUndiversifiedKeyWith32ByteKey(): void
    {
        $kdf = new KeyDerivation();
        $masterKey = hex2bin('47BBB68AFA73F31310BEEFCE5DDA692DBAD671A03FEAD5A9BBDBCF3CD6D4C521');

        $result = $kdf->deriveUndiversifiedKey($masterKey, 1);

        $this->assertSame(16, strlen($result));
        $this->assertSame('c3b653d8484d82fd9d5dc48840e1f94e', bin2hex($result));
    }

    /**
     * Test deriveUndiversifiedKey with 16-byte master key.
     */
    public function testDeriveUndiversifiedKeyWith16ByteKey(): void
    {
        $kdf = new KeyDerivation();
        $masterKey = hex2bin('C9EB67DF090AFF47C3B19A2516680B9D');

        $result = $kdf->deriveUndiversifiedKey($masterKey, 1);

        $this->assertSame(16, strlen($result));
    }

    /**
     * Test deriveTagKey with 32-byte master key.
     */
    public function testDeriveTagKeyWith32ByteKey(): void
    {
        $kdf = new KeyDerivation();
        $masterKey = hex2bin('47BBB68AFA73F31310BEEFCE5DDA692DBAD671A03FEAD5A9BBDBCF3CD6D4C521');
        $uid = hex2bin('04c24eda926980');

        $result = $kdf->deriveTagKey($masterKey, $uid, 2);

        $this->assertSame(16, strlen($result));
    }

    /**
     * Test deriveTagKey with 16-byte master key.
     */
    public function testDeriveTagKeyWith16ByteKey(): void
    {
        $kdf = new KeyDerivation();
        $masterKey = hex2bin('C9EB67DF090AFF47C3B19A2516680B9D');
        $uid = hex2bin('010203040506AB');

        $result = $kdf->deriveTagKey($masterKey, $uid, 1);

        $this->assertSame(16, strlen($result));
    }

    /**
     * Test deriveTagKey with key number 2.
     */
    public function testDeriveTagKeyWithKeyNumber2(): void
    {
        $kdf = new KeyDerivation();
        $masterKey = hex2bin('B95F4C27E3D0BC333792EA968545217F');
        $uid = hex2bin('05050505050505');

        $result = $kdf->deriveTagKey($masterKey, $uid, 2);

        $this->assertSame(16, strlen($result));
        $this->assertSame('89ae686de793fdf48057ee6e78505cfc', bin2hex($result));
    }

    /**
     * Test deriveUndiversifiedKey with factory key returns zeros.
     */
    public function testDeriveUndiversifiedKeyFactoryKeyReturnsZeros(): void
    {
        $kdf = new KeyDerivation();
        $factoryKey = hex2bin('00000000000000000000000000000000');

        $result = $kdf->deriveUndiversifiedKey($factoryKey, 1);

        $this->assertSame('00000000000000000000000000000000', bin2hex($result));
    }

    /**
     * Test deriveTagKey with factory key returns zeros.
     */
    public function testDeriveTagKeyFactoryKeyReturnsZeros(): void
    {
        $kdf = new KeyDerivation();
        $factoryKey = hex2bin('00000000000000000000000000000000');
        $uid = hex2bin('010203040506AB');

        $result = $kdf->deriveTagKey($factoryKey, $uid, 1);

        $this->assertSame('00000000000000000000000000000000', bin2hex($result));
    }

    /**
     * Test deriveTagKey with factory key and key number 2.
     */
    public function testDeriveTagKeyFactoryKeyKeyNumber2(): void
    {
        $kdf = new KeyDerivation();
        $factoryKey = hex2bin('00000000000000000000000000000000');
        $uid = hex2bin('03030303030303');

        $result = $kdf->deriveTagKey($factoryKey, $uid, 2);

        $this->assertSame('00000000000000000000000000000000', bin2hex($result));
    }
}
