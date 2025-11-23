<?php

declare(strict_types=1);

namespace KDuma\SDM;

/**
 * Encryption mode for NTAG 424 DNA SDM.
 */
enum EncMode: int
{
    case AES = 0;
    case LRP = 1;
}
