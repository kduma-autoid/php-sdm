<?php

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use KDuma\SDM\KeyDerivation;
use KDuma\SDM\SDM;

class SDMServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Register KeyDerivation as a singleton
        $this->app->singleton(KeyDerivation::class, function ($app) {
            return new KeyDerivation;
        });

        // Register a factory for creating SDM instances
        $this->app->bind('sdm.factory', function ($app) {
            return function (?string $uid = null) use ($app): SDM {
                $masterKeyHex = config('sdm.master_key');
                $masterKey = hex2bin($masterKeyHex);

                if ($masterKey === false) {
                    throw new \InvalidArgumentException('Invalid master key format');
                }

                /** @var KeyDerivation $kdf */
                $kdf = $app->make(KeyDerivation::class);

                // If UID is provided, derive tag-specific keys
                if ($uid !== null) {
                    $encKey = $kdf->deriveTagKey($masterKey, $uid, 1);
                    $macKey = $kdf->deriveTagKey($masterKey, $uid, 2);
                } else {
                    // Otherwise, derive undiversified keys
                    $encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);
                    $macKey = $encKey; // Use same key for both
                }

                return new SDM(
                    encKey: $encKey,
                    macKey: $macKey,
                    sdmmacParam: config('sdm.params.sdmmac')
                );
            };
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        //
    }
}
