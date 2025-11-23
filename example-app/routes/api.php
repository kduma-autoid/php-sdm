<?php

use App\Http\Controllers\SDMController;
use Illuminate\Support\Facades\Route;

// Plain SUN message validation
Route::get('/tagpt', [SDMController::class, 'apiTagPlainText']);

// SUN message decryption
Route::get('/tag', [SDMController::class, 'apiTag']);

// Tamper-tag SUN message decryption
Route::get('/tagtt', [SDMController::class, 'apiTagTamper']);
