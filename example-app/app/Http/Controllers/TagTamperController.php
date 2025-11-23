<?php

declare(strict_types=1);

namespace App\Http\Controllers;

class TagTamperController extends TagController
{
    /**
     * Determine if this is a tamper tag.
     */
    protected function isTamperTag(): bool
    {
        return true;
    }
}
