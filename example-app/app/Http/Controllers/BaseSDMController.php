<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use KDuma\SDM\SDM;

abstract class BaseSDMController extends Controller
{
    /**
     * Get SDM instance.
     */
    protected function getSDM(?string $uid = null): SDM
    {
        $factory = app('sdm.factory');

        return $factory($uid);
    }

    /**
     * Get master key from configuration.
     */
    protected function getMasterKey(): string
    {
        $masterKeyHex = config('sdm.master_key');
        $masterKey = hex2bin($masterKeyHex);

        if ($masterKey === false) {
            throw new \InvalidArgumentException('Invalid master key format');
        }

        return $masterKey;
    }

    /**
     * Get encryption key.
     */
    protected function getEncKey(): string
    {
        $masterKey = $this->getMasterKey();
        $kdf = app(\KDuma\SDM\KeyDerivation::class);

        return $kdf->deriveUndiversifiedKey($masterKey, 1);
    }

    /**
     * Get MAC key for a specific UID.
     */
    protected function getMacKey(string $uid): string
    {
        $masterKey = $this->getMasterKey();
        $kdf = app(\KDuma\SDM\KeyDerivation::class);

        return $kdf->deriveTagKey($masterKey, $uid, 2);
    }
}
