# PHP SDM - Complete Documentation

This document provides detailed information on how to use the PHP SDM library for NTAG 424 DNA Secure Dynamic Messaging.

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [Key Derivation](#key-derivation)
5. [Decrypting SDM Messages](#decrypting-sdm-messages)
6. [Validating Plain SUN Messages](#validating-plain-sun-messages)
7. [Encryption Modes](#encryption-modes)
8. [Parameter Modes](#parameter-modes)
9. [Advanced Usage](#advanced-usage)
10. [Error Handling](#error-handling)
11. [Security Considerations](#security-considerations)
12. [Examples](#examples)

## Introduction

NTAG 424 DNA is an NFC tag that supports Secure Dynamic Messaging (SDM), which allows tags to generate cryptographically authenticated URLs that change with each scan. This library provides PHP implementations of:

- **SDM message decryption** - Decrypt encrypted PICC data and file data
- **CMAC validation** - Verify message authentication codes
- **Key derivation** - Generate session keys from master keys
- **UID diversification** - Tag-specific key derivation

The library follows the specifications in:
- NXP AN12196 (NTAG 424 DNA features)
- NXP AN12304 (Leakage Resilient Primitive)
- NIST SP 800-108 (Key Derivation Functions)

## Installation

Install via Composer:

```bash
composer require kduma/php-sdm
```

## Core Concepts

### NTAG 424 DNA

NTAG 424 DNA tags can be configured to generate dynamic URLs that include:

1. **Encrypted PICC Data** - Contains UID, read counter, and configuration
2. **Encrypted File Data** - Optional application-specific data
3. **SDMMAC** - Message authentication code (CMAC)

### SUN Messages

Secure Unique NFC (SUN) messages come in two types:

1. **Plain SUN** - Unencrypted UID and read counter with CMAC
2. **Encrypted SUN** - Encrypted PICC data with optional file data and CMAC

### Encryption Modes

NTAG 424 DNA supports two encryption modes:

- **AES** - Standard AES-128 encryption (16-byte encrypted PICC data)
- **LRP** - Leakage Resilient Primitive (24-byte encrypted PICC data)

## Key Derivation

The library implements NIST SP 800-108 key derivation with UID diversification.

### Master Key Setup

Your master key should be a 16-32 byte binary string, typically derived from your NTAG configuration:

```php
use KDuma\SDM\KeyDerivation;

$masterKey = hex2bin('C9EB67DF090AFF47C3B19A2516680B9D');
$kdf = new KeyDerivation();
```

### Undiversified Keys

Used for PICC data encryption (not UID-specific):

```php
// Derive encryption key (key number 1)
$encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);
```

**Note:** Only key number 1 is supported for undiversified keys.

### UID-Diversified Keys

Used for file data encryption and CMAC (tag-specific):

```php
// UID is 7 bytes
$uid = hex2bin('04E12AB3CD5E80');

// Derive MAC key (key number 2)
$macKey = $kdf->deriveTagKey($masterKey, $uid, 2);

// Or derive file read key (key number 1)
$fileKey = $kdf->deriveTagKey($masterKey, $uid, 1);
```

**Key Numbers:**
- `1` - File read key
- `2` - MAC key

### Factory Keys

The library recognizes factory keys (all zeros) and returns them unchanged:

```php
$factoryKey = str_repeat("\x00", 16);
$result = $kdf->deriveUndiversifiedKey($factoryKey, 1);
// Returns: "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
```

## Decrypting SDM Messages

### Basic Decryption

The simplest way to decrypt an SDM message:

```php
use KDuma\SDM\SDM;

$sdm = new SDM(
    encKey: $encKey,
    macKey: $macKey
);

// Decrypt the message
$result = $sdm->decrypt(
    encData: hex2bin('EF963FF7828658A599F3041510671E88'),
    encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962'),
    cmac: hex2bin('94EED9EE65337086')
);

// Result contains:
// [
//     'picc_data_tag' => "\xC7",
//     'uid' => "\x04\x1E\x3C\x8A\x2D\x6B\x80",
//     'read_ctr' => 6,
//     'file_data' => "\x43\x43",
//     'encryption_mode' => EncMode::AES
// ]
```

### Advanced Decryption with Callable Keys

For more control, use `decryptSunMessage()` with a callable for dynamic key derivation:

```php
use KDuma\SDM\ParamMode;
use KDuma\SDM\KeyDerivation;

$kdf = new KeyDerivation();
$masterKey = hex2bin('your_master_key');

// Create SDM instance with undiversified key
$sdm = new SDM(
    encKey: $kdf->deriveUndiversifiedKey($masterKey, 1),
    macKey: '', // Not used when providing callable
);

$result = $sdm->decryptSunMessage(
    paramMode: ParamMode::SEPARATED,
    sdmMetaReadKey: $kdf->deriveUndiversifiedKey($masterKey, 1),
    sdmFileReadKey: function(string $uid) use ($kdf, $masterKey): string {
        // Derive tag-specific key after UID is decrypted
        return $kdf->deriveTagKey($masterKey, $uid, 2);
    },
    piccEncData: hex2bin($piccData),
    sdmmac: hex2bin($cmac),
    encFileData: hex2bin($encFileData)
);
```

### Without File Data

If the tag doesn't use encrypted file data:

```php
$result = $sdm->decrypt(
    encData: hex2bin($piccData),
    encFileData: hex2bin(''), // Empty string
    cmac: hex2bin($cmac)
);

// file_data will be null
```

## Validating Plain SUN Messages

Plain SUN messages contain unencrypted UID and read counter with CMAC validation.

### Simple Validation

```php
use KDuma\SDM\SDM;

$sdm = new SDM(
    encKey: $encKey,
    macKey: $macKey
);

// Data is UID (7 bytes) + read counter (3 bytes)
$data = hex2bin('041E3C8A2D6B80000006');
$cmac = hex2bin('4B00064004B0B3D3');

$isValid = $sdm->validate($data, $cmac);
// Returns: true or false
```

### Detailed Validation

For more information about the validated message:

```php
use KDuma\SDM\EncMode;

$result = $sdm->validatePlainSun(
    uid: hex2bin('041E3C8A2D6B80'),
    readCtr: hex2bin('000006'),
    sdmmac: hex2bin('4B00064004B0B3D3'),
    sdmFileReadKey: $macKey,
    mode: EncMode::AES
);

// Result contains:
// [
//     'encryption_mode' => EncMode::AES,
//     'uid' => "\x04\x1E\x3C\x8A\x2D\x6B\x80",
//     'read_ctr' => 6
// ]
```

**Note:** Read counter in `validatePlainSun()` is in little-endian format, while the returned integer is the actual counter value.

## Encryption Modes

### Detecting Encryption Mode

The library automatically detects the encryption mode from PICC data length:

```php
$mode = $sdm->getEncryptionMode($piccEncData);

if ($mode === EncMode::AES) {
    // 16-byte PICC data - AES mode
} elseif ($mode === EncMode::LRP) {
    // 24-byte PICC data - LRP mode
}
```

### AES Mode

Standard AES-128 encryption:

- PICC encrypted data: 16 bytes
- Uses AES-CBC with zero IV for PICC data
- Session keys derived via AES-CMAC

```php
$result = $sdm->decryptSunMessage(
    // ... parameters ...
    piccEncData: hex2bin('EF963FF7828658A599F3041510671E88'), // 16 bytes
);
// encryption_mode will be EncMode::AES
```

### LRP Mode

Leakage Resilient Primitive for enhanced security:

- PICC encrypted data: 24 bytes (8-byte random + 16-byte encrypted data)
- Uses LRP cipher with PICC random as counter
- Session keys derived via LRP CMAC

```php
$result = $sdm->decryptSunMessage(
    // ... parameters ...
    piccEncData: hex2bin('1234567890ABCDEF...'), // 24 bytes
);
// encryption_mode will be EncMode::LRP
```

**Note:** LRP mode is detected automatically. No manual mode selection is needed.

## Parameter Modes

SDM URLs can encode parameters in two ways:

### Separated Mode

Each parameter has its own name:

```
https://example.com/tag?picc_data=xxx&enc=yyy&cmac=zzz
```

```php
use KDuma\SDM\ParamMode;

$result = $sdm->decryptSunMessage(
    paramMode: ParamMode::SEPARATED,
    // ... other parameters ...
);
```

### Bulk Mode

All parameters concatenated without names:

```
https://example.com/tag?data=xxxyyyzzz
```

```php
use KDuma\SDM\ParamMode;

$result = $sdm->decryptSunMessage(
    paramMode: ParamMode::BULK,
    // ... other parameters ...
);
```

**Note:** Parameter mode affects CMAC calculation. Use the mode that matches your tag configuration.

## Advanced Usage

### Custom SDMMAC Parameter Name

If your SDM URL uses a custom parameter name for CMAC:

```php
$sdm = new SDM(
    encKey: $encKey,
    macKey: $macKey,
    sdmmacParam: 'mac' // Default is 'cmac'
);
```

This affects CMAC calculation for separated mode with file data.

### Manual CMAC Calculation

Calculate SDMMAC manually:

```php
use KDuma\SDM\ParamMode;
use KDuma\SDM\EncMode;

$piccData = $uid . strrev($readCtr); // UID + reversed read counter

$sdmmac = $sdm->calculateSdmmac(
    paramMode: ParamMode::SEPARATED,
    sdmFileReadKey: $macKey,
    piccData: $piccData,
    encFileData: $encFileData, // or null if not used
    mode: EncMode::AES
);
```

### Manual File Data Decryption

Decrypt file data separately:

```php
$fileData = $sdm->decryptFileData(
    sdmFileReadKey: $fileKey,
    piccData: $uid . strrev($readCtr),
    readCtr: $readCtr, // 3-byte little-endian
    encFileData: $encryptedData,
    mode: EncMode::AES
);
```

## Error Handling

The library throws specific exceptions for different error conditions:

### DecryptionException

Thrown when decryption fails:

```php
use KDuma\SDM\Exceptions\DecryptionException;

try {
    $result = $sdm->decrypt($encData, $encFileData, $cmac);
} catch (DecryptionException $e) {
    // Invalid encrypted data, wrong key, or malformed input
    echo "Decryption failed: " . $e->getMessage();
}
```

**Common causes:**
- Invalid encryption key
- Malformed encrypted data
- Incorrect data length
- Unsupported encryption mode

### ValidationException

Thrown when CMAC validation fails:

```php
use KDuma\SDM\Exceptions\ValidationException;

try {
    $result = $sdm->decrypt($encData, $encFileData, $cmac);
} catch (ValidationException $e) {
    // Invalid CMAC - message has been tampered with
    echo "Validation failed: " . $e->getMessage();
}
```

**Common causes:**
- Wrong MAC key
- Tampered data
- Incorrect CMAC value
- Mismatched parameter mode

### InvalidArgumentException

Thrown for invalid input parameters:

```php
try {
    $key = $kdf->deriveTagKey($masterKey, $uid, 3); // Invalid key number
} catch (\InvalidArgumentException $e) {
    echo "Invalid parameter: " . $e->getMessage();
}
```

### Exception Hierarchy

```
\Exception
└── KDuma\SDM\Exceptions\SDMException
    ├── DecryptionException
    └── ValidationException
```

## Security Considerations

### Key Storage

- Never hardcode keys in source code
- Store master keys in secure configuration files or environment variables
- Use key derivation instead of storing multiple keys
- Rotate keys periodically

### CMAC Validation

- Always validate CMAC before trusting decrypted data
- Use constant-time comparison (`hash_equals()`) to prevent timing attacks
- The library uses `hash_equals()` internally

### Read Counter

- Verify read counter increments to prevent replay attacks
- Store last seen counter per UID
- Reject messages with lower or equal counters

### UID Verification

- Verify UID matches expected tag when applicable
- Use UID diversification for tag-specific keys
- Check UID length (must be 7 bytes for NTAG 424 DNA)

### Factory Keys

- Never use factory keys (all zeros) in production
- The library detects factory keys but does not prevent their use
- Change default keys before deployment

## Examples

### Example 1: Web Application URL Handler

```php
<?php

use KDuma\SDM\SDM;
use KDuma\SDM\KeyDerivation;
use KDuma\SDM\Exceptions\DecryptionException;
use KDuma\SDM\Exceptions\ValidationException;

// Configuration
$masterKey = hex2bin(getenv('SDM_MASTER_KEY'));
$kdf = new KeyDerivation();

// Parse URL parameters
$piccData = $_GET['picc_data'] ?? '';
$encFileData = $_GET['enc'] ?? '';
$cmac = $_GET['cmac'] ?? '';

try {
    // Derive keys
    $encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);

    // Create SDM instance
    $sdm = new SDM($encKey, '');

    // Decrypt message with dynamic MAC key derivation
    $result = $sdm->decryptSunMessage(
        paramMode: \KDuma\SDM\ParamMode::SEPARATED,
        sdmMetaReadKey: $encKey,
        sdmFileReadKey: fn($uid) => $kdf->deriveTagKey($masterKey, $uid, 2),
        piccEncData: hex2bin($piccData),
        sdmmac: hex2bin($cmac),
        encFileData: $encFileData ? hex2bin($encFileData) : null
    );

    // Display results
    echo "UID: " . bin2hex($result['uid']) . "\n";
    echo "Read Counter: " . $result['read_ctr'] . "\n";
    echo "Encryption: " . $result['encryption_mode']->name . "\n";

    if ($result['file_data']) {
        echo "File Data: " . bin2hex($result['file_data']) . "\n";
    }

} catch (ValidationException $e) {
    http_response_code(403);
    echo "Invalid signature: " . $e->getMessage();
} catch (DecryptionException $e) {
    http_response_code(400);
    echo "Decryption error: " . $e->getMessage();
}
```

### Example 2: Plain SUN Validation with Counter Tracking

```php
<?php

use KDuma\SDM\SDM;
use KDuma\SDM\KeyDerivation;

class CounterTracker
{
    private array $counters = [];

    public function validateAndTrack(string $uid, int $readCtr): bool
    {
        $uidHex = bin2hex($uid);

        // Check if we've seen this UID before
        if (isset($this->counters[$uidHex])) {
            $lastCounter = $this->counters[$uidHex];

            // Reject if counter didn't increment
            if ($readCtr <= $lastCounter) {
                return false;
            }
        }

        // Update counter
        $this->counters[$uidHex] = $readCtr;
        return true;
    }
}

$tracker = new CounterTracker();
$masterKey = hex2bin(getenv('SDM_MASTER_KEY'));
$kdf = new KeyDerivation();

// Parse parameters
$uid = hex2bin($_GET['uid']);
$readCtr = hex2bin($_GET['ctr']);
$cmac = hex2bin($_GET['cmac']);

// Derive MAC key
$macKey = $kdf->deriveTagKey($masterKey, $uid, 2);
$sdm = new SDM('', $macKey);

try {
    // Validate CMAC
    $result = $sdm->validatePlainSun(
        uid: $uid,
        readCtr: $readCtr,
        sdmmac: $cmac,
        sdmFileReadKey: $macKey
    );

    // Check counter
    if (!$tracker->validateAndTrack($result['uid'], $result['read_ctr'])) {
        http_response_code(403);
        echo "Replay attack detected!";
        exit;
    }

    echo "Valid scan from UID: " . bin2hex($result['uid']) . "\n";
    echo "Counter: " . $result['read_ctr'] . "\n";

} catch (\Exception $e) {
    http_response_code(400);
    echo "Validation failed: " . $e->getMessage();
}
```

### Example 3: Tamper Tag Detection

```php
<?php

use KDuma\SDM\SDM;
use KDuma\SDM\KeyDerivation;

function interpretTamperStatus(string $fileData): array
{
    if (strlen($fileData) < 2) {
        return ['status' => 'Invalid', 'color' => 'gray'];
    }

    $statusBytes = substr($fileData, 0, 2);

    return match ($statusBytes) {
        "\xCC\xCC" => ['status' => 'Secure', 'color' => 'green'],
        "\x0C\xCC" => ['status' => 'Tampered (Closed)', 'color' => 'red'],
        "\x0C\x0C" => ['status' => 'Tampered (Open)', 'color' => 'red'],
        "\xCD\xCD" => ['status' => 'Uninitialized', 'color' => 'orange'],
        default => ['status' => 'Unknown', 'color' => 'gray'],
    };
}

$masterKey = hex2bin(getenv('SDM_MASTER_KEY'));
$kdf = new KeyDerivation();
$encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);

$sdm = new SDM($encKey, '');

$result = $sdm->decryptSunMessage(
    paramMode: \KDuma\SDM\ParamMode::SEPARATED,
    sdmMetaReadKey: $encKey,
    sdmFileReadKey: fn($uid) => $kdf->deriveTagKey($masterKey, $uid, 2),
    piccEncData: hex2bin($_GET['picc_data']),
    sdmmac: hex2bin($_GET['cmac']),
    encFileData: hex2bin($_GET['enc'])
);

if ($result['file_data']) {
    $tamperStatus = interpretTamperStatus($result['file_data']);
    echo "Tamper Status: " . $tamperStatus['status'] . "\n";
    echo "UID: " . bin2hex($result['uid']) . "\n";
    echo "Counter: " . $result['read_ctr'] . "\n";
}
```

### Example 4: Batch Validation

```php
<?php

use KDuma\SDM\SDM;
use KDuma\SDM\KeyDerivation;
use KDuma\SDM\ParamMode;

$masterKey = hex2bin(getenv('SDM_MASTER_KEY'));
$kdf = new KeyDerivation();
$encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);

$sdm = new SDM($encKey, '');

$scans = [
    [
        'picc_data' => 'EF963FF7828658A599F3041510671E88',
        'enc' => 'CEE9A53E3E463EF1F459635736738962',
        'cmac' => '94EED9EE65337086',
    ],
    // ... more scans
];

$results = [];

foreach ($scans as $scan) {
    try {
        $result = $sdm->decryptSunMessage(
            paramMode: ParamMode::SEPARATED,
            sdmMetaReadKey: $encKey,
            sdmFileReadKey: fn($uid) => $kdf->deriveTagKey($masterKey, $uid, 2),
            piccEncData: hex2bin($scan['picc_data']),
            sdmmac: hex2bin($scan['cmac']),
            encFileData: hex2bin($scan['enc'])
        );

        $results[] = [
            'success' => true,
            'uid' => bin2hex($result['uid']),
            'counter' => $result['read_ctr'],
            'mode' => $result['encryption_mode']->name,
        ];

    } catch (\Exception $e) {
        $results[] = [
            'success' => false,
            'error' => $e->getMessage(),
        ];
    }
}

echo json_encode($results, JSON_PRETTY_PRINT);
```

---

For API reference, see [API.md](API.md).

For the example Laravel application, see [EXAMPLE_APP.md](EXAMPLE_APP.md).
