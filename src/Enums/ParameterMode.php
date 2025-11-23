<?php

declare(strict_types=1);

namespace KDuma\SDM\Enums;

/**
 * SDM parameter modes
 */
enum ParameterMode: string
{
    /**
     * Parameters are separated in the URL (e.g., ?picc_data=...&enc=...&cmac=...)
     */
    case SEPARATED = 'SEPARATED';

    /**
     * Parameters are combined/bulk encoded
     */
    case BULK = 'BULK';

    /**
     * Plain SUN mode (no encryption, only MAC validation)
     */
    case PLAIN = 'PLAIN';
}
