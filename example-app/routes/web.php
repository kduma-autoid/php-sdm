<?php

use App\Http\Controllers\SDMController;
use Illuminate\Support\Facades\Route;

// Main page
Route::view('/', 'main');

// WebNFC interface
Route::view('/webnfc', 'webnfc');

// Plain SUN message validation
Route::get('/tagpt', [SDMController::class, 'tagPlainText']);

// SUN message decryption
Route::get('/tag', [SDMController::class, 'tag']);

// Tamper-tag SUN message decryption
Route::get('/tagtt', [SDMController::class, 'tagTamper']);
