<?php

declare(strict_types=1);

namespace KDuma\SDM\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Base test case for SDM tests.
 */
abstract class SDMTestCase extends TestCase
{
    /**
     * Set up test environment.
     */
    protected function setUp(): void
    {
        parent::setUp();
    }

    /**
     * Tear down test environment.
     */
    protected function tearDown(): void
    {
        parent::tearDown();
    }
}
