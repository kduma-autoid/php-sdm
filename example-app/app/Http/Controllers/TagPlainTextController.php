<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Helpers\ParameterParser;
use App\Http\Responses\ErrorResponse;
use App\Http\Responses\ValidResponse;
use Illuminate\Http\Request;
use KDuma\SDM\Exceptions\ValidationException;

class TagPlainTextController extends BaseSDMController
{
    /**
     * Handle the incoming request.
     */
    public function __invoke(Request $request)
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
}
