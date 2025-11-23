<?php

declare(strict_types=1);

require __DIR__.'/vendor/autoload.php';

use KDuma\SDM\Cipher\LRPCipher;

echo "=== LRP Debug: Comparing PHP vs Python Reference ===\n\n";

// Test 1: Basic AES-ECB encryption
echo "Test 1: Basic AES-ECB encryption\n";
echo "--------------------------------\n";
$key = hex2bin('00000000000000000000000000000000');
$data = hex2bin('55555555555555555555555555555555');

$encrypted = openssl_encrypt(
    $data,
    'AES-128-ECB',
    $key,
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);

echo "Key:       ".bin2hex($key)."\n";
echo "Data:      ".bin2hex($data)."\n";
echo "Encrypted: ".bin2hex($encrypted)."\n";
echo "Expected:  dc095347589c0677e9a943f5c6b8bcd6 (from Python)\n\n";

// Test 2: Algorithm 1 - Generate Plaintexts step by step
echo "Test 2: Algorithm 1 - Generate Plaintexts (first few steps)\n";
echo "-----------------------------------------------------------\n";
$key = hex2bin('00000000000000000000000000000000');

echo "Initial key: ".bin2hex($key)."\n\n";

// Step 1: h = e(key, 0x55...)
$h = openssl_encrypt(
    str_repeat("\x55", 16),
    'AES-128-ECB',
    $key,
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);
echo "Step 1 - h = e(key, 0x55...): ".bin2hex($h)."\n";
echo "Expected (Python):             dc095347589c0677e9a943f5c6b8bcd6\n\n";

// Step 2: p[0] = e(h, 0xaa...)
$p0 = openssl_encrypt(
    str_repeat("\xaa", 16),
    'AES-128-ECB',
    $h,
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);
echo "Step 2 - p[0] = e(h, 0xaa...): ".bin2hex($p0)."\n";
echo "Expected (Python):              c6a13b37878f5b826f4f8162a1c8d879\n\n";

// Step 3: h = e(h, 0x55...)
$h = openssl_encrypt(
    str_repeat("\x55", 16),
    'AES-128-ECB',
    $h,
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);
echo "Step 3 - h = e(h, 0x55...): ".bin2hex($h)."\n\n";

// Test using the LRPCipher class
echo "Test 3: Using LRPCipher::generatePlaintexts()\n";
echo "----------------------------------------------\n";
$plaintexts = LRPCipher::generatePlaintexts($key);
echo "p[0]:  ".bin2hex($plaintexts[0])."\n";
echo "Expected: c6a13b37878f5b826f4f8162a1c8d879\n\n";
echo "p[15]: ".bin2hex($plaintexts[15])."\n";
echo "Expected: 55bfe6b5abc5ca5de45d1e213d259f5c\n\n";

// Test 4: Algorithm 2 - Generate Updated Keys
echo "Test 4: Algorithm 2 - Generate Updated Keys\n";
echo "-------------------------------------------\n";

// Step 1: h = e(key, 0xaa...)
$h = openssl_encrypt(
    str_repeat("\xaa", 16),
    'AES-128-ECB',
    $key,
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);
echo "Step 1 - h = e(key, 0xaa...): ".bin2hex($h)."\n";
echo "Expected (Python):             6cda81459e5e7eba48bcd8dd90dc0027\n\n";

// Step 2: uk[0] = e(h, 0xaa...)
$uk0 = openssl_encrypt(
    str_repeat("\xaa", 16),
    'AES-128-ECB',
    $h,
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);
echo "Step 2 - uk[0] = e(h, 0xaa...): ".bin2hex($uk0)."\n";
echo "Expected (Python):               eba0b0a857d6eba7e7f25e9eaf6cb697\n\n";

$updatedKeys = LRPCipher::generateUpdatedKeys($key);
echo "Using LRPCipher::generateUpdatedKeys():\n";
echo "uk[0]: ".bin2hex($updatedKeys[0])."\n";
echo "Expected: eba0b0a857d6eba7e7f25e9eaf6cb697\n\n";
echo "uk[2]: ".bin2hex($updatedKeys[2])."\n";
echo "Expected: b52d9ea628eef96d8beb0d0f8468c4c0\n\n";

// Test 5: Check if parameter order might be the issue
echo "Test 5: Testing parameter order hypothesis\n";
echo "------------------------------------------\n";
echo "Testing if swapping key/data parameters makes a difference:\n\n";

// Normal: encrypt(data, key)
$result1 = openssl_encrypt(
    str_repeat("\x55", 16),
    'AES-128-ECB',
    $key,
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);
echo "openssl_encrypt(0x55..., key): ".bin2hex($result1)."\n";

// Try with different approach
$result2 = openssl_encrypt(
    $key,
    'AES-128-ECB',
    str_repeat("\x55", 16),
    OPENSSL_RAW_DATA | OPENSSL_NO_PADDING
);
echo "openssl_encrypt(key, 0x55...): ".bin2hex($result2)."\n";
echo "Expected from Python:          dc095347589c0677e9a943f5c6b8bcd6\n\n";
