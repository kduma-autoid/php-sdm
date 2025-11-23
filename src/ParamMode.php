<?php

declare(strict_types=1);

namespace KDuma\SDM;

/**
 * Parameter mode for dynamic URL encoding.
 */
enum ParamMode: int
{
    case SEPARATED = 0;
    case BULK = 1;
}
