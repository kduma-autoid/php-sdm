<?php

declare(strict_types=1);

namespace KDuma\SDM\Exceptions;

/**
 * Thrown when CMAC signature verification fails.
 * 
 * This typically indicates:
 * - Message has been tampered with
 * - Incorrect MAC key
 * - Message corruption during transmission
 * - Replay attack attempt
 */
class InvalidSignatureException extends SDMException
{
}
