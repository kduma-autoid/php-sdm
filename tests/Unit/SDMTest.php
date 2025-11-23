<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\SDM;
use PHPUnit\Framework\TestCase;

class SDMTest extends TestCase
{
    public function test_can_be_instantiated(): void
    {
        $sdm = new SDM('encryption_key', 'mac_key');

        $this->assertInstanceOf(SDM::class, $sdm);
    }

    // TODO: Add more tests
}
