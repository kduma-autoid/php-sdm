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
                'encryptionMode' => $result['encryption_mode']->value,
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
                'encryption_mode' => $result['encryption_mode']->value,
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

            // Check if LRP mode is requested but not supported
            if ($params['mode'] === 'LRP') {
                return $this->errorResponse('LRP mode is not yet supported in the php-sdm library', 501);
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
                'encryptionMode' => $result['encryption_mode']->value,
                'uid' => $result['uid'],
                'readCtr' => $result['read_ctr'],
                'fileData' => $result['file_data'],
                'fileDataUtf8' => $result['file_data'] ? mb_convert_encoding($result['file_data'], 'UTF-8', 'UTF-8') : null,
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

            // Check if LRP mode is requested but not supported
            if ($params['mode'] === 'LRP') {
                return $this->jsonErrorResponse('LRP mode is not yet supported in the php-sdm library', 501);
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
                'encryption_mode' => $result['encryption_mode']->value,
                'uid' => bin2hex($result['uid']),
                'read_ctr' => $result['read_ctr'],
            ];

            if ($result['file_data']) {
                $responseData['file_data'] = bin2hex($result['file_data']);
                $responseData['file_data_utf8'] = mb_convert_encoding($result['file_data'], 'UTF-8', 'UTF-8');
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
     * Get encryption key.
     */
    private function getEncKey(): string
    {
        $masterKeyHex = config('sdm.master_key');
        $masterKey = hex2bin($masterKeyHex);

        if ($masterKey === false) {
            throw new \InvalidArgumentException('Invalid master key format');
        }

        $kdf = app(\KDuma\SDM\KeyDerivation::class);

        return $kdf->deriveUndiversifiedKey($masterKey, 1);
    }

    /**
     * Get MAC key for a specific UID.
     */
    private function getMacKey(string $uid): string
    {
        $masterKeyHex = config('sdm.master_key');
        $masterKey = hex2bin($masterKeyHex);

        if ($masterKey === false) {
            throw new \InvalidArgumentException('Invalid master key format');
        }

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
