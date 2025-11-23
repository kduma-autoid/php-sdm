<?php

use App\Http\Controllers\TagController;
use App\Http\Controllers\TagPlainTextController;
use App\Http\Controllers\TagTamperController;
use Illuminate\Support\Facades\Route;

// Main page
Route::view('/', 'main');

// WebNFC interface
Route::view('/webnfc', 'webnfc');

// Plain SUN message validation
Route::get('/tagpt', TagPlainTextController::class);

// SUN message decryption
Route::get('/tag', TagController::class);

// Tamper-tag SUN message decryption
Route::get('/tagtt', TagTamperController::class);
