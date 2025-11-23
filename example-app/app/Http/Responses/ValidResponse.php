<?php

declare(strict_types=1);

namespace App\Http\Responses;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;

class ValidResponse implements Responsable
{
    /**
     * Binary fields that should be hex-encoded for JSON responses.
     */
    private const BINARY_FIELDS = ['uid', 'picc_data_tag', 'file_data'];

    public function __construct(
        private readonly array $data,
        private readonly int $status = 200
    ) {}

    public function toResponse($request): Response|JsonResponse
    {
        if ($request->wantsJson()) {
            return response()->json(
                $this->convertBinaryToHex($this->data),
                $this->status,
                [],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
            );
        }

        return response()->view('info', $this->convertKeysToCamelCase($this->data), $this->status);
    }

    /**
     * Convert binary fields to hex for JSON responses.
     */
    private function convertBinaryToHex(array $data): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            if (in_array($key, self::BINARY_FIELDS) && is_string($value)) {
                $result[$key] = bin2hex($value);
            } else {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    /**
     * Convert snake_case keys to camelCase for view responses.
     */
    private function convertKeysToCamelCase(array $data): array
    {
        $result = [];

        foreach ($data as $key => $value) {
            $camelKey = lcfirst(str_replace('_', '', ucwords($key, '_')));
            $result[$camelKey] = $value;
        }

        return $result;
    }
}
