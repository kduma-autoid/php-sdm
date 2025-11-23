<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Helpers\ParameterParser;
use App\Http\Responses\ErrorResponse;
use App\Http\Responses\ValidResponse;
use Illuminate\Http\Request;
use KDuma\SDM\Exceptions\DecryptionException;
use KDuma\SDM\Exceptions\ValidationException;

class TagController extends BaseSDMController
{
    /**
     * Handle the incoming request.
     */
    public function __invoke(Request $request)
    {
        try {
            $params = ParameterParser::parseEncryptedParams($request);

            $sdm = $this->getSDM();

            $result = $sdm->decryptSunMessage(
                paramMode: \KDuma\SDM\ParamMode::SEPARATED,
                sdmMetaReadKey: $this->getEncKey(),
                sdmFileReadKey: fn (string $uid) => $this->getMacKey($uid),
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
            if ($this->isTamperTag() && $result['file_data']) {
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
     * Determine if this is a tamper tag.
     */
    protected function isTamperTag(): bool
    {
        return false;
    }

    /**
     * Convert binary data to UTF-8 string safely.
     */
    protected function convertToUtf8(string $data): string
    {
        // Check if data is already valid UTF-8
        if (mb_check_encoding($data, 'UTF-8')) {
            return $data;
        }

        // Treat as ISO-8859-1 (Latin1) and convert to UTF-8
        // This ensures every byte is mapped to a valid character
        return mb_convert_encoding($data, 'UTF-8', 'ISO-8859-1');
    }
}
