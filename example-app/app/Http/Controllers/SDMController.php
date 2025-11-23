<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Helpers\ParameterParser;
use App\Http\Responses\ErrorResponse;
use App\Http\Responses\ValidResponse;
use Illuminate\Http\Request;
use KDuma\SDM\Exceptions\DecryptionException;
use KDuma\SDM\Exceptions\ValidationException;
use KDuma\SDM\SDM;

class SDMController extends Controller
{
    /**
     * Plain SUN message validation (HTML).
     */
    public function tagPlainText(Request $request)
    {
        try {
            $params = ParameterParser::parsePlainParams($request);

            $sdm = $this->getSDM();

            $result = $sdm->validatePlainSun(
                uid: $params['uid'],
                readCtr: $params['ctr'],
                sdmmac: $params['sdmmac'],
                sdmFileReadKey: $this->getMacKey($params['uid'])
            );

            return new ValidResponse([
                'encryption_mode' => $result['encryption_mode']->name,
                'uid' => $result['uid'],
                'read_ctr' => $result['read_ctr'],
                'file_data' => null,
                'file_data_utf8' => null,
            ]);
        } catch (ValidationException $e) {
            return new ErrorResponse($e->getMessage(), 403);
        } catch (\InvalidArgumentException $e) {
            return new ErrorResponse($e->getMessage(), 400);
        }
    }

    /**
     * Plain SUN message validation (JSON API).
     */
    public function apiTagPlainText(Request $request)
    {
        try {
            $params = ParameterParser::parsePlainParams($request);

            $sdm = $this->getSDM();

            $result = $sdm->validatePlainSun(
                uid: $params['uid'],
                readCtr: $params['ctr'],
                sdmmac: $params['sdmmac'],
                sdmFileReadKey: $this->getMacKey($params['uid'])
            );

            return new ValidResponse([
                'encryption_mode' => $result['encryption_mode']->name,
                'uid' => $result['uid'],
                'read_ctr' => $result['read_ctr'],
            ]);
        } catch (ValidationException $e) {
            return new ErrorResponse($e->getMessage(), 403);
        } catch (\InvalidArgumentException $e) {
            return new ErrorResponse($e->getMessage(), 400);
        }
    }

    /**
     * SUN message decryption (HTML).
     */
    public function tag(Request $request)
    {
        return $this->processEncryptedTag($request, false);
    }

    /**
     * SUN message decryption (JSON API).
     */
    public function apiTag(Request $request)
    {
        return $this->processEncryptedTagApi($request, false);
    }

    /**
     * Tamper-tag SUN message decryption (HTML).
     */
    public function tagTamper(Request $request)
    {
        return $this->processEncryptedTag($request, true);
    }

    /**
     * Tamper-tag SUN message decryption (JSON API).
     */
    public function apiTagTamper(Request $request)
    {
        return $this->processEncryptedTagApi($request, true);
    }

    /**
     * Process encrypted tag (common logic for tag and tagTamper).
     */
    private function processEncryptedTag(Request $request, bool $isTamperTag)
    {
        try {
            $params = ParameterParser::parseEncryptedParams($request);

            $sdm = $this->getSDM();

            $result = $sdm->decryptSunMessage(
                paramMode: \KDuma\SDM\ParamMode::SEPARATED,
                sdmMetaReadKey: $this->getEncKey(),
                sdmFileReadKey: fn(string $uid) => $this->getMacKey($uid),
                piccEncData: $params['picc_data'],
                sdmmac: $params['sdmmac'],
                encFileData: $params['enc_file_data']
            );

            $responseData = [
                'picc_data_tag' => $result['picc_data_tag'],
                'encryption_mode' => $result['encryption_mode']->name,
                'uid' => $result['uid'],
                'read_ctr' => $result['read_ctr'],
                'file_data' => $result['file_data'],
                'file_data_utf8' => $result['file_data'] ? $this->convertToUtf8($result['file_data']) : null,
            ];

            // Add tamper status if this is a tamper tag
            if ($isTamperTag && $result['file_data']) {
                $tamperInfo = ParameterParser::interpretTamperStatus($result['file_data']);
                if ($tamperInfo) {
                    $responseData['tamper_status'] = $tamperInfo['status'];
                    $responseData['tamper_color'] = $tamperInfo['color'];
                }
            }

            return new ValidResponse($responseData);
        } catch (ValidationException $e) {
            return new ErrorResponse($e->getMessage(), 403);
        } catch (DecryptionException $e) {
            return new ErrorResponse($e->getMessage(), 400);
        } catch (\InvalidArgumentException $e) {
            return new ErrorResponse($e->getMessage(), 400);
        } catch (\RuntimeException $e) {
            return new ErrorResponse($e->getMessage(), 501);
        }
    }

    /**
     * Process encrypted tag API (common logic for API routes).
     */
    private function processEncryptedTagApi(Request $request, bool $isTamperTag)
    {
        try {
            $params = ParameterParser::parseEncryptedParams($request);

            $sdm = $this->getSDM();

            $result = $sdm->decryptSunMessage(
                paramMode: \KDuma\SDM\ParamMode::SEPARATED,
                sdmMetaReadKey: $this->getEncKey(),
                sdmFileReadKey: fn(string $uid) => $this->getMacKey($uid),
                piccEncData: $params['picc_data'],
                sdmmac: $params['sdmmac'],
                encFileData: $params['enc_file_data']
            );

            $responseData = [
                'picc_data_tag' => $result['picc_data_tag'],
                'encryption_mode' => $result['encryption_mode']->name,
                'uid' => $result['uid'],
                'read_ctr' => $result['read_ctr'],
                'file_data' => $result['file_data'],
                'file_data_utf8' => $result['file_data'] ? $this->convertToUtf8($result['file_data']) : null,
            ];

            // Add tamper status if this is a tamper tag
            if ($isTamperTag && $result['file_data']) {
                $tamperInfo = ParameterParser::interpretTamperStatus($result['file_data']);
                if ($tamperInfo) {
                    $responseData['tamper_status'] = $tamperInfo['status'];
                }
            }

            return new ValidResponse($responseData);
        } catch (ValidationException $e) {
            return new ErrorResponse($e->getMessage(), 403);
        } catch (DecryptionException $e) {
            return new ErrorResponse($e->getMessage(), 400);
        } catch (\InvalidArgumentException $e) {
            return new ErrorResponse($e->getMessage(), 400);
        } catch (\RuntimeException $e) {
            return new ErrorResponse($e->getMessage(), 501);
        }
    }

    /**
     * Get SDM instance.
     */
    private function getSDM(?string $uid = null): SDM
    {
        $factory = app('sdm.factory');

        return $factory($uid);
    }

    /**
     * Convert binary data to UTF-8 string safely.
     */
    private function convertToUtf8(string $data): string
    {
        // Check if data is already valid UTF-8
        if (mb_check_encoding($data, 'UTF-8')) {
            return $data;
        }

        // Treat as ISO-8859-1 (Latin1) and convert to UTF-8
        // This ensures every byte is mapped to a valid character
        return mb_convert_encoding($data, 'UTF-8', 'ISO-8859-1');
    }

    /**
     * Get master key from configuration.
     */
    private function getMasterKey(): string
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
    private function getEncKey(): string
    {
        $masterKey = $this->getMasterKey();
        $kdf = app(\KDuma\SDM\KeyDerivation::class);

        return $kdf->deriveUndiversifiedKey($masterKey, 1);
    }

    /**
     * Get MAC key for a specific UID.
     */
    private function getMacKey(string $uid): string
    {
        $masterKey = $this->getMasterKey();
        $kdf = app(\KDuma\SDM\KeyDerivation::class);

        return $kdf->deriveTagKey($masterKey, $uid, 2);
    }

}
