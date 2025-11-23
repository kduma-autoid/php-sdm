<?php

declare(strict_types=1);

namespace App\Http\Responses;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;

class ErrorResponse implements Responsable
{
    public function __construct(
        private readonly string $message,
        private readonly int $status = 400
    ) {}

    public function toResponse($request): Response|JsonResponse
    {
        if ($request->wantsJson()) {
            return response()->json(
                ['error' => $this->message],
                $this->status,
                [],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
            );
        }

        return response()->view('error', ['message' => $this->message], $this->status);
    }
}
