<?php

declare(strict_types=1);

namespace App\Helpers;

use Illuminate\Http\Request;

class ParameterParser
{
    /**
     * Parse SDM parameters from request.
     *
     * Supports two modes:
     * 1. Bulk mode: Single 'e' parameter containing all data
     * 2. Separated mode: Individual parameters (picc_data, enc, cmac)
     *
     * @return array{picc_data: string, enc_file_data: string|null, sdmmac: string, mode: string}
     */
    public static function parseEncryptedParams(Request $request): array
    {
        $paramNames = config('sdm.params');

        // Check for bulk mode (single 'e' parameter)
        if ($request->has('e')) {
            return self::parseBulkMode($request->input('e'), $paramNames['sdmmac']);
        }

        // Separated mode
        $piccData = $request->input($paramNames['enc_picc_data']);
        $encFileData = $request->input($paramNames['enc_file_data']);
        $sdmmac = $request->input($paramNames['sdmmac']);

        if (!$piccData || !$sdmmac) {
            throw new \InvalidArgumentException('Missing required parameters');
        }

        // Decode hex strings to binary
        $piccDataBin = hex2bin($piccData);
        $sdmmacBin = hex2bin($sdmmac);

        if ($piccDataBin === false || $sdmmacBin === false) {
            throw new \InvalidArgumentException('Failed to decode parameters');
        }

        $encFileDataBin = null;
        if ($encFileData) {
            $encFileDataBin = hex2bin($encFileData);
            if ($encFileDataBin === false) {
                throw new \InvalidArgumentException('Failed to decode enc_file_data parameter');
            }
        }

        // Detect encryption mode based on PICC data length
        $mode = self::detectEncryptionMode($piccDataBin);

        return [
            'picc_data' => $piccDataBin,
            'enc_file_data' => $encFileDataBin,
            'sdmmac' => $sdmmacBin,
            'mode' => $mode,
        ];
    }

    /**
     * Parse plain SUN parameters from request.
     *
     * @return array{uid: string, ctr: string, sdmmac: string}
     */
    public static function parsePlainParams(Request $request): array
    {
        $paramNames = config('sdm.params');

        $uid = $request->input($paramNames['uid']);
        $ctr = $request->input($paramNames['ctr']);
        $sdmmac = $request->input($paramNames['sdmmac']);

        if (!$uid || !$ctr || !$sdmmac) {
            throw new \InvalidArgumentException('Missing required parameters');
        }

        // Decode hex strings to binary
        $uidBin = hex2bin($uid);
        $ctrBin = hex2bin($ctr);
        $sdmmacBin = hex2bin($sdmmac);

        if ($uidBin === false || $ctrBin === false || $sdmmacBin === false) {
            throw new \InvalidArgumentException('Failed to decode parameters');
        }

        return [
            'uid' => $uidBin,
            'ctr' => $ctrBin,
            'sdmmac' => $sdmmacBin,
        ];
    }

    /**
     * Parse bulk mode parameter (single 'e' parameter).
     *
     * Format: [PICC_DATA][ENC_FILE_DATA (optional)][SDMMAC]&cmac=
     */
    private static function parseBulkMode(string $bulkParam, string $sdmmacParamName): array
    {
        // Remove the SDMMAC parameter suffix if present
        $sdmmacSuffix = '&' . $sdmmacParamName . '=';
        $bulkParam = str_replace($sdmmacSuffix, '', $bulkParam);

        // Decode the hex string
        $data = hex2bin($bulkParam);
        if ($data === false) {
            throw new \InvalidArgumentException('Failed to decode bulk parameter');
        }

        // SDMMAC is always the last 8 bytes
        $sdmmac = substr($data, -8);
        $remaining = substr($data, 0, -8);

        // Detect encryption mode based on PICC data length
        // First, try 16 bytes (AES)
        if (strlen($remaining) >= 16) {
            $piccData = substr($remaining, 0, 16);
            $encFileData = strlen($remaining) > 16 ? substr($remaining, 16) : null;
            $mode = 'AES';
        } elseif (strlen($remaining) >= 24) {
            // Try 24 bytes (LRP)
            $piccData = substr($remaining, 0, 24);
            $encFileData = strlen($remaining) > 24 ? substr($remaining, 24) : null;
            $mode = 'LRP';
        } else {
            throw new \InvalidArgumentException('Invalid PICC data length');
        }

        return [
            'picc_data' => $piccData,
            'enc_file_data' => $encFileData,
            'sdmmac' => $sdmmac,
            'mode' => $mode,
        ];
    }

    /**
     * Detect encryption mode based on PICC data length.
     *
     * @param  string  $piccData Binary PICC data
     * @return string 'AES' or 'LRP'
     */
    private static function detectEncryptionMode(string $piccData): string
    {
        $length = strlen($piccData);

        return match ($length) {
            16 => 'AES',
            24 => 'LRP',
            default => throw new \InvalidArgumentException(
                sprintf('Invalid PICC data length: %d bytes (expected 16 for AES or 24 for LRP)', $length)
            ),
        };
    }

    /**
     * Interpret tamper tag status from file data.
     *
     * @param  string  $fileData Binary file data
     * @return array{status: string, color: string}|null
     */
    public static function interpretTamperStatus(string $fileData): ?array
    {
        if (strlen($fileData) < 2) {
            return null;
        }

        $byte1 = $fileData[0];
        $byte2 = $fileData[1];

        return match (true) {
            $byte1 === 'C' && $byte2 === 'C' => [
                'status' => 'Secure',
                'color' => 'success',
            ],
            $byte1 === 'O' && $byte2 === 'C' => [
                'status' => 'Tampered (Closed)',
                'color' => 'danger',
            ],
            $byte1 === 'O' && $byte2 === 'O' => [
                'status' => 'Tampered (Open)',
                'color' => 'danger',
            ],
            $byte1 === 'I' && $byte2 === 'I' => [
                'status' => 'Uninitialized',
                'color' => 'warning',
            ],
            $byte1 === 'N' && $byte2 === 'T' => [
                'status' => 'Not TagTamper',
                'color' => 'warning',
            ],
            default => [
                'status' => 'Unknown',
                'color' => 'secondary',
            ],
        };
    }
}
