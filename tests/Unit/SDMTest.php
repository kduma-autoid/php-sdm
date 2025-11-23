<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests\Unit;

use KDuma\SDM\SDM;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversNothing]
final class SDMTest extends TestCase
{
    public function testCanBeInstantiated(): void
    {
        $sdm = new SDM('encryption_key', 'mac_key');

        $this->assertInstanceOf(SDM::class, $sdm);
    }

    // TODO: Add more tests
}
