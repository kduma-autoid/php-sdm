<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Helpers\ParameterParser;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use KDuma\SDM\Exceptions\DecryptionException;
use KDuma\SDM\Exceptions\ValidationException;
use KDuma\SDM\SDM;

class SDMController extends Controller
{
    /**
     * Main landing page.
     */
    public function index(): View
    {
        return view('main');
    }

    /**
     * WebNFC interface page.
     */
    public function webnfc(): View
    {
        return view('webnfc');
    }

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

            return view('info', [
                'encryptionMode' => $result['encryption_mode']->name,
                'uid' => $result['uid'],
                'readCtr' => $result['read_ctr'],
                'fileData' => null,
                'fileDataUtf8' => null,
            ]);
        } catch (ValidationException $e) {
            return $this->errorResponse($e->getMessage(), 403);
        } catch (\InvalidArgumentException $e) {
            return $this->errorResponse($e->getMessage(), 400);
        }
    }

    /**
     * Plain SUN message validation (JSON API).
     */
    public function apiTagPlainText(Request $request): JsonResponse
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

            return $this->jsonResponse([
                'encryption_mode' => $result['encryption_mode']->name,
                'uid' => bin2hex($result['uid']),
                'read_ctr' => $result['read_ctr'],
            ]);
        } catch (ValidationException $e) {
            return $this->jsonErrorResponse($e->getMessage(), 403);
        } catch (\InvalidArgumentException $e) {
            return $this->jsonErrorResponse($e->getMessage(), 400);
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
    public function apiTag(Request $request): JsonResponse
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
    public function apiTagTamper(Request $request): JsonResponse
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

            // Check for LRP mode requirement
            if (config('sdm.require_lrp') && $params['mode'] !== 'LRP') {
                return $this->errorResponse('LRP mode is required', 400);
            }

            $sdm = $this->getSDM();

            $result = $sdm->decryptSunMessage(
                paramMode: \KDuma\SDM\ParamMode::SEPARATED,
                sdmMetaReadKey: $this->getEncKey(),
                sdmFileReadKey: fn(string $uid) => $this->getMacKey($uid),
                piccEncData: $params['picc_data'],
                sdmmac: $params['sdmmac'],
                encFileData: $params['enc_file_data']
            );

            $viewData = [
                'piccDataTag' => $result['picc_data_tag'],
                'encryptionMode' => $result['encryption_mode']->name,
                'uid' => $result['uid'],
                'readCtr' => $result['read_ctr'],
                'fileData' => $result['file_data'],
                'fileDataUtf8' => $result['file_data'] ? $this->convertToUtf8($result['file_data']) : null,
            ];

            // Add tamper status if this is a tamper tag
            if ($isTamperTag && $result['file_data']) {
                $tamperInfo = ParameterParser::interpretTamperStatus($result['file_data']);
                if ($tamperInfo) {
                    $viewData['tamperStatus'] = $tamperInfo['status'];
                    $viewData['tamperColor'] = $tamperInfo['color'];
                }
            }

            return view('info', $viewData);
        } catch (ValidationException $e) {
            return $this->errorResponse($e->getMessage(), 403);
        } catch (DecryptionException $e) {
            return $this->errorResponse($e->getMessage(), 400);
        } catch (\InvalidArgumentException $e) {
            return $this->errorResponse($e->getMessage(), 400);
        } catch (\RuntimeException $e) {
            return $this->errorResponse($e->getMessage(), 501);
        }
    }

    /**
     * Process encrypted tag API (common logic for API routes).
     */
    private function processEncryptedTagApi(Request $request, bool $isTamperTag): JsonResponse
    {
        try {
            $params = ParameterParser::parseEncryptedParams($request);

            // Check for LRP mode requirement
            if (config('sdm.require_lrp') && $params['mode'] !== 'LRP') {
                return $this->jsonErrorResponse('LRP mode is required', 400);
            }

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
                'picc_data_tag' => bin2hex($result['picc_data_tag']),
                'encryption_mode' => $result['encryption_mode']->name,
                'uid' => bin2hex($result['uid']),
                'read_ctr' => $result['read_ctr'],
            ];

            if ($result['file_data']) {
                $responseData['file_data'] = bin2hex($result['file_data']);
                $responseData['file_data_utf8'] = $this->convertToUtf8($result['file_data']);
            }

            // Add tamper status if this is a tamper tag
            if ($isTamperTag && $result['file_data']) {
                $tamperInfo = ParameterParser::interpretTamperStatus($result['file_data']);
                if ($tamperInfo) {
                    $responseData['tamper_status'] = $tamperInfo['status'];
                }
            }

            return $this->jsonResponse($responseData);
        } catch (ValidationException $e) {
            return $this->jsonErrorResponse($e->getMessage(), 403);
        } catch (DecryptionException $e) {
            return $this->jsonErrorResponse($e->getMessage(), 400);
        } catch (\InvalidArgumentException $e) {
            return $this->jsonErrorResponse($e->getMessage(), 400);
        } catch (\RuntimeException $e) {
            return $this->jsonErrorResponse($e->getMessage(), 501);
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

    /**
     * Return error view.
     */
    private function errorResponse(string $message, int $status = 400)
    {
        return response()->view('error', ['message' => $message], $status);
    }

    /**
     * Return JSON response with pretty printing.
     */
    private function jsonResponse(array $data, int $status = 200): JsonResponse
    {
        return response()->json($data, $status, [], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Return JSON error response.
     */
    private function jsonErrorResponse(string $message, int $status = 400): JsonResponse
    {
        return $this->jsonResponse(['error' => $message], $status);
    }
}
