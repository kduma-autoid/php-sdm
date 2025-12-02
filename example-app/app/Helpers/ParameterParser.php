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

        // Validate required parameters are present and non-empty
        if (empty($piccData) || empty($sdmmac)) {
            throw new \InvalidArgumentException(
                sprintf('Missing required parameters: %s, %s', $paramNames['enc_picc_data'], $paramNames['sdmmac'])
            );
        }

        // Validate and decode hex strings
        $piccDataBin = self::validateAndDecodeHex($piccData, $paramNames['enc_picc_data']);
        $sdmmacBin = self::validateAndDecodeHex($sdmmac, $paramNames['sdmmac']);

        $encFileDataBin = null;
        if (! empty($encFileData)) {
            $encFileDataBin = self::validateAndDecodeHex($encFileData, $paramNames['enc_file_data']);
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

        // Validate required parameters are present and non-empty
        if (empty($uid) || empty($ctr) || empty($sdmmac)) {
            throw new \InvalidArgumentException(
                sprintf('Missing required parameters: %s, %s, %s', $paramNames['uid'], $paramNames['ctr'], $paramNames['sdmmac'])
            );
        }

        // Validate and decode hex strings
        $uidBin = self::validateAndDecodeHex($uid, $paramNames['uid']);
        $ctrBin = self::validateAndDecodeHex($ctr, $paramNames['ctr']);
        $sdmmacBin = self::validateAndDecodeHex($sdmmac, $paramNames['sdmmac']);

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
        // Validate bulk parameter is not empty
        if (empty($bulkParam)) {
            throw new \InvalidArgumentException('Bulk parameter is empty');
        }

        // Remove the SDMMAC parameter suffix if present
        $sdmmacSuffix = '&'.$sdmmacParamName.'=';
        $bulkParam = str_replace($sdmmacSuffix, '', $bulkParam);

        // Validate hex string length is even
        if (strlen($bulkParam) % 2 !== 0) {
            throw new \InvalidArgumentException('Bulk parameter must have even length');
        }

        // Decode the hex string
        $data = hex2bin($bulkParam);
        if ($data === false) {
            throw new \InvalidArgumentException('Failed to decode bulk parameter: invalid hexadecimal format');
        }

        // SDMMAC is always the last 8 bytes
        $sdmmac = substr($data, -8);
        $remaining = substr($data, 0, -8);

        // Detect encryption mode based on PICC data length
        // Check for LRP (24 bytes) first, then AES (16 bytes)
        if (strlen($remaining) >= 24) {
            $piccData = substr($remaining, 0, 24);
            $encFileData = strlen($remaining) > 24 ? substr($remaining, 24) : null;
            $mode = 'LRP';
        } elseif (strlen($remaining) >= 16) {
            $piccData = substr($remaining, 0, 16);
            $encFileData = strlen($remaining) > 16 ? substr($remaining, 16) : null;
            $mode = 'AES';
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
     * @param  string  $piccData  Binary PICC data
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
     * Validate and decode a hexadecimal string parameter.
     *
     * @param  string  $value      The hex string to validate and decode
     * @param  string  $paramName  The parameter name (for error messages)
     *
     * @return string The decoded binary string
     *
     * @throws \InvalidArgumentException if validation or decoding fails
     */
    private static function validateAndDecodeHex(string $value, string $paramName): string
    {
        // Validate hex string length is even
        if (strlen($value) % 2 !== 0) {
            throw new \InvalidArgumentException(
                sprintf('Invalid %s parameter: must have even length', $paramName)
            );
        }

        // Decode hex string to binary
        $decoded = hex2bin($value);
        if ($decoded === false) {
            throw new \InvalidArgumentException(
                sprintf('Failed to decode %s parameter: invalid hexadecimal format', $paramName)
            );
        }

        return $decoded;
    }

    /**
     * Interpret tamper tag status from file data.
     *
     * @param  string  $fileData  Binary file data
     * @return array{status: string, color: string}|null
     */
    public static function interpretTamperStatus(string $fileData): ?array
    {
        if (strlen($fileData) < 2) {
            return null;
        }

        // Use substr() for safe byte extraction
        $byte1 = substr($fileData, 0, 1);
        $byte2 = substr($fileData, 1, 1);

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
