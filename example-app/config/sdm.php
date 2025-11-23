<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | SDM Master Key
    |--------------------------------------------------------------------------
    |
    | The master cryptographic key used for deriving per-tag encryption keys.
    | This should be a 32-character hexadecimal string (16 bytes).
    |
    | When set to all zeros (00000000000000000000000000000000), the application
    | runs in demo mode with example data and GitHub attribution links.
    |
    */

    'master_key' => env('SDM_MASTER_KEY', '00000000000000000000000000000000'),

    /*
    |--------------------------------------------------------------------------
    | Demo Mode Detection
    |--------------------------------------------------------------------------
    |
    | Demo mode is automatically enabled when the master key is all zeros.
    | In demo mode, the application shows example URLs and GitHub links.
    |
    */

    'demo_mode' => env('SDM_MASTER_KEY', '00000000000000000000000000000000') === '00000000000000000000000000000000',

    /*
    |--------------------------------------------------------------------------
    | SDM URL Parameter Names
    |--------------------------------------------------------------------------
    |
    | These define the parameter names used in SDM URLs for various data fields.
    | These match the parameter names from the Python Flask reference implementation.
    |
    */

    'params' => [
        'enc_picc_data' => env('SDM_ENC_PICC_DATA_PARAM', 'picc_data'),
        'enc_file_data' => env('SDM_ENC_FILE_DATA_PARAM', 'enc'),
        'uid' => env('SDM_UID_PARAM', 'uid'),
        'ctr' => env('SDM_CTR_PARAM', 'ctr'),
        'sdmmac' => env('SDM_SDMMAC_PARAM', 'cmac'),
    ],

    /*
    |--------------------------------------------------------------------------
    | LRP Mode Requirement
    |--------------------------------------------------------------------------
    |
    | When enabled, this will enforce LRP encryption mode and reject AES requests.
    | Note: LRP mode is not yet implemented in the php-sdm library.
    |
    */

    'require_lrp' => env('SDM_REQUIRE_LRP', false),
];
