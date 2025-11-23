<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\KeyDerivation;
use PHPUnit\Framework\TestCase;

class KeyDerivationTest extends TestCase
{
    private KeyDerivation $kdf;

    protected function setUp(): void
    {
        $this->kdf = new KeyDerivation();
    }

    /**
     * Test key derivation with factory key (all zeros)
     * Based on test_kdf_factory_key from Python tests
     */
    public function test_kdf_factory_key(): void
    {
        $masterKey = hex2bin('00000000000000000000000000000000');
        $this->assertNotFalse($masterKey);

        // Test derive_undiversified_key with factory key
        $result = $this->kdf->deriveUndiversifiedKey($masterKey, 1);
        $this->assertSame(
            '00000000000000000000000000000000',
            bin2hex($result),
            'Factory key should produce all zeros for undiversified key derivation'
        );

        // Test derive_tag_key with factory key and UID 010203040506AB
        $uid1 = hex2bin('010203040506AB');
        $this->assertNotFalse($uid1);
        $result = $this->kdf->deriveTagKey($masterKey, $uid1, 1);
        $this->assertSame(
            '00000000000000000000000000000000',
            bin2hex($result),
            'Factory key should produce all zeros for tag key derivation with UID 010203040506AB'
        );

        // Test derive_tag_key with factory key and UID 03030303030303, key number 2
        $uid2 = hex2bin('03030303030303');
        $this->assertNotFalse($uid2);
        $result = $this->kdf->deriveTagKey($masterKey, $uid2, 2);
        $this->assertSame(
            '00000000000000000000000000000000',
            bin2hex($result),
            'Factory key should produce all zeros for tag key derivation with UID 03030303030303 and key number 2'
        );
    }

    /**
     * Test key derivation with K1 master key
     * Based on test_kdf_k1 from Python tests
     */
    public function test_kdf_k1(): void
    {
        $masterKey = hex2bin('C9EB67DF090AFF47C3B19A2516680B9D');
        $this->assertNotFalse($masterKey);

        // Test derive_undiversified_key
        $result = $this->kdf->deriveUndiversifiedKey($masterKey, 1);
        $this->assertSame(
            'a13086f194d7bdfd108dd11716ea2bdf',
            bin2hex($result),
            'K1 undiversified key derivation failed'
        );

        // Test derive_tag_key with UID 010203040506AB
        $uid1 = hex2bin('010203040506AB');
        $this->assertNotFalse($uid1);
        $result = $this->kdf->deriveTagKey($masterKey, $uid1, 1);
        $this->assertSame(
            'f18cdd9389d47ae7ab381e80e5ab6fe3',
            bin2hex($result),
            'K1 tag key derivation with UID 010203040506AB failed'
        );

        // Test derive_tag_key with UID 03030303030303, key number 2
        $uid2 = hex2bin('03030303030303');
        $this->assertNotFalse($uid2);
        $result = $this->kdf->deriveTagKey($masterKey, $uid2, 2);
        $this->assertSame(
            '85f7cc459a5b4b2f5d1a5019ded61c88',
            bin2hex($result),
            'K1 tag key derivation with UID 03030303030303 and key number 2 failed'
        );
    }

    /**
     * Test key derivation with K2 master key
     * Based on test_kdf_k2 from Python tests
     */
    public function test_kdf_k2(): void
    {
        $masterKey = hex2bin('B95F4C27E3D0BC333792EA968545217F');
        $this->assertNotFalse($masterKey);

        // Test derive_undiversified_key
        $result = $this->kdf->deriveUndiversifiedKey($masterKey, 1);
        $this->assertSame(
            '3a553c40846fda656faa0fce4f45fdbd',
            bin2hex($result),
            'K2 undiversified key derivation failed'
        );

        // Test derive_tag_key with UID 010203040506AB
        $uid1 = hex2bin('010203040506AB');
        $this->assertNotFalse($uid1);
        $result = $this->kdf->deriveTagKey($masterKey, $uid1, 1);
        $this->assertSame(
            '00883874c67dd23032b2acd10d771635',
            bin2hex($result),
            'K2 tag key derivation with UID 010203040506AB failed'
        );

        // Test derive_tag_key with UID 05050505050505, key number 2
        $uid2 = hex2bin('05050505050505');
        $this->assertNotFalse($uid2);
        $result = $this->kdf->deriveTagKey($masterKey, $uid2, 2);
        $this->assertSame(
            '89ae686de793fdf48057ee6e78505cfc',
            bin2hex($result),
            'K2 tag key derivation with UID 05050505050505 and key number 2 failed'
        );
    }
}
