# Example Application Documentation

This Laravel application demonstrates real-world usage of the PHP SDM library for processing NTAG 424 DNA Secure Dynamic Messaging data.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Routes and Endpoints](#routes-and-endpoints)
6. [Usage Examples](#usage-examples)
7. [Architecture](#architecture)
8. [WebNFC Interface](#webnfc-interface)
9. [Demo Mode](#demo-mode)
10. [Response Formats](#response-formats)
11. [Deployment](#deployment)

## Overview

The example application is a PHP/Laravel port of the Python Flask [nfc-developer/sdm-backend](https://github.com/nfc-developer/sdm-backend) application. It provides both HTML and JSON endpoints for validating and decrypting NTAG 424 DNA SDM messages.

**Location:** `/example-app` directory

**Framework:** Laravel 12.x

**Purpose:** Demonstrate production-ready implementation of the PHP SDM library

## Features

- **Plain SUN Message Validation** - Validate plaintext UID with mirrored read counter and CMAC
- **Encrypted SUN Message Decryption** - Decrypt and validate encrypted PICC and file data
- **Tamper-Tag Support** - Detect and report tamper status from TagTamper variant tags
- **Dual Output** - HTML views for browsers and JSON API endpoints for programmatic access
- **WebNFC Interface** - Browser-based NFC tag scanning (Chrome for Android only)
- **Demo Mode** - Automatic example data when using factory keys (all zeros)
- **AES and LRP Support** - Automatic detection and handling of both encryption modes
- **Key Derivation** - Proper UID diversification using NIST SP 800-108

## Installation

### Step 1: Navigate to Example App

```bash
cd example-app
```

### Step 2: Install Dependencies

```bash
composer install
```

Dependencies are already configured in `composer.json` and include the parent library via path repository.

### Step 3: Environment Setup

The `.env` file is already configured with demo mode enabled (all-zeros master key).

For production use with real tags, edit `.env`:

```bash
SDM_MASTER_KEY=your_32_character_hex_master_key
```

### Step 4: Start Development Server

```bash
php artisan serve
```

The application will be available at `http://localhost:8000`.

### Step 5: Test the Application

Open your browser to:
- `http://localhost:8000` - Main landing page with examples
- `http://localhost:8000/webnfc` - WebNFC scanning interface (Chrome on Android only)

## Configuration

All SDM-related configuration is in `config/sdm.php` and can be overridden via `.env`.

### Master Key Configuration

```bash
SDM_MASTER_KEY=00000000000000000000000000000000
```

- **Format:** 32-character hexadecimal string (16 bytes)
- **Demo Mode:** All zeros activates demo mode with example URLs
- **Production:** Use your actual master key from NTAG 424 DNA tag configuration

### URL Parameter Names

Customize the parameter names used in SDM URLs:

```bash
SDM_ENC_PICC_DATA_PARAM=picc_data
SDM_ENC_FILE_DATA_PARAM=enc
SDM_UID_PARAM=uid
SDM_CTR_PARAM=ctr
SDM_SDMMAC_PARAM=cmac
```

These should match your NTAG 424 DNA tag configuration.

### LRP Mode Requirement

```bash
SDM_REQUIRE_LRP=false
```

When enabled, the application enforces LRP encryption mode and rejects AES requests.

**Note:** LRP mode is fully supported in the library and application.

### Configuration File

**File:** `example-app/config/sdm.php`

```php
return [
    'master_key' => env('SDM_MASTER_KEY', '00000000000000000000000000000000'),
    'enc_picc_data_param' => env('SDM_ENC_PICC_DATA_PARAM', 'picc_data'),
    'enc_file_data_param' => env('SDM_ENC_FILE_DATA_PARAM', 'enc'),
    'uid_param' => env('SDM_UID_PARAM', 'uid'),
    'ctr_param' => env('SDM_CTR_PARAM', 'ctr'),
    'sdmmac_param' => env('SDM_SDMMAC_PARAM', 'cmac'),
    'require_lrp' => env('SDM_REQUIRE_LRP', false),
    'is_demo_mode' => env('SDM_MASTER_KEY', '00000000000000000000000000000000') === '00000000000000000000000000000000',
];
```

## Routes and Endpoints

### Web Routes (HTML Output)

| Route | Description | Parameters |
|-------|-------------|------------|
| `GET /` | Main landing page | None |
| `GET /webnfc` | WebNFC scanning interface | None |
| `GET /tagpt` | Plain SUN validation | `uid`, `ctr`, `cmac` |
| `GET /tag` | Encrypted SUN decryption | `picc_data`, `cmac`, `enc` (optional) |
| `GET /tagtt` | Tamper-tag decryption | `picc_data`, `cmac`, `enc` |

### API Routes (JSON Output)

| Route | Description | Parameters |
|-------|-------------|------------|
| `GET /api/tagpt` | Plain SUN validation (JSON) | `uid`, `ctr`, `cmac` |
| `GET /api/tag` | SUN decryption (JSON) | `picc_data`, `cmac`, `enc` (optional) |
| `GET /api/tagtt` | Tamper-tag decryption (JSON) | `picc_data`, `cmac`, `enc` |

### Route Definitions

**File:** `example-app/routes/web.php`

```php
use App\Http\Controllers\SDMController;

// Main page
Route::get('/', [SDMController::class, 'index']);

// WebNFC interface
Route::get('/webnfc', [SDMController::class, 'webnfc']);

// Plain SUN message validation
Route::get('/tagpt', [SDMController::class, 'tagPlainText']);
Route::get('/api/tagpt', [SDMController::class, 'apiTagPlainText']);

// SUN message decryption
Route::get('/tag', [SDMController::class, 'tag']);
Route::get('/api/tag', [SDMController::class, 'apiTag']);

// Tamper-tag SUN message decryption
Route::get('/tagtt', [SDMController::class, 'tagTamper']);
Route::get('/api/tagtt', [SDMController::class, 'apiTagTamper']);
```

## Usage Examples

### Example 1: Plain SUN Validation

Validate a plain SUN message with unencrypted UID and read counter.

**HTML Output:**

```bash
curl "http://localhost:8000/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3"
```

**JSON Output:**

```bash
curl "http://localhost:8000/api/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3"
```

**Response (JSON):**

```json
{
    "encryption_mode": "AES",
    "uid": "041e3c8a2d6b80",
    "read_ctr": 6
}
```

### Example 2: Encrypted SUN (AES Mode)

Decrypt an encrypted SUN message without file data.

**Request:**

```bash
curl "http://localhost:8000/api/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"
```

**Response:**

```json
{
    "picc_data_tag": "c7",
    "encryption_mode": "AES",
    "uid": "041e3c8a2d6b80",
    "read_ctr": 6
}
```

### Example 3: Encrypted SUN with File Data

Decrypt SUN message including encrypted file data.

**Request:**

```bash
curl "http://localhost:8000/api/tag?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6"
```

**Response:**

```json
{
    "picc_data_tag": "c7",
    "encryption_mode": "AES",
    "uid": "041e3c8a2d6b80",
    "read_ctr": 23,
    "file_data": "4343",
    "file_data_utf8": "CC"
}
```

### Example 4: Tamper-Tag Detection

Detect tamper status from TagTamper variant tags.

**Request:**

```bash
curl "http://localhost:8000/api/tagtt?picc_data=FDD387BF32A33A7C40CF259675B3A1E2&enc=EA050C282D8E9043E28F7A171464D697&cmac=758110182134ECE9"
```

**Response:**

```json
{
    "picc_data_tag": "c7",
    "encryption_mode": "AES",
    "uid": "041e3c8a2d6b80",
    "read_ctr": 42,
    "file_data": "4343",
    "file_data_utf8": "CC",
    "tamper_status": "Secure"
}
```

### Example 5: LRP Mode Detection

The application automatically detects and handles LRP mode.

**Request:**

```bash
# LRP mode has 24-byte picc_data (vs 16 bytes for AES)
curl "http://localhost:8000/api/tag?picc_data=1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF&cmac=..."
```

**Response:**

```json
{
    "encryption_mode": "LRP",
    ...
}
```

### Example 6: Error Handling

**Invalid CMAC:**

```bash
curl "http://localhost:8000/api/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=0000000000000000"
```

**Response (403 Forbidden):**

```json
{
    "error": "Message is not properly signed - invalid MAC"
}
```

**Invalid Data:**

```bash
curl "http://localhost:8000/api/tag?picc_data=INVALID&cmac=94EED9EE65337086"
```

**Response (400 Bad Request):**

```json
{
    "error": "Invalid encrypted PICC data length - expected 16 bytes (AES) or 24 bytes (LRP), got 3 bytes. This may indicate malformed or truncated input data."
}
```

## Architecture

### Directory Structure

```
example-app/
├── app/
│   ├── Helpers/
│   │   └── ParameterParser.php      # URL parameter parsing
│   ├── Http/
│   │   └── Controllers/
│   │       └── SDMController.php    # Main controller
│   └── Providers/
│       └── SDMServiceProvider.php   # Key derivation service
├── config/
│   └── sdm.php                      # SDM configuration
├── resources/
│   └── views/
│       ├── layouts/
│       │   └── app.blade.php        # Base layout
│       ├── main.blade.php           # Landing page
│       ├── info.blade.php           # Result display
│       ├── error.blade.php          # Error display
│       └── webnfc.blade.php         # WebNFC interface
└── routes/
    └── web.php                      # Route definitions
```

### Key Components

#### SDMController

**File:** `app/Http/Controllers/SDMController.php`

Main controller handling all SDM operations.

**Methods:**
- `index()` - Landing page
- `webnfc()` - WebNFC interface
- `tagPlainText()` - Plain SUN validation (HTML)
- `apiTagPlainText()` - Plain SUN validation (JSON)
- `tag()` - Encrypted SUN decryption (HTML)
- `apiTag()` - Encrypted SUN decryption (JSON)
- `tagTamper()` - Tamper-tag decryption (HTML)
- `apiTagTamper()` - Tamper-tag decryption (JSON)

#### ParameterParser

**File:** `app/Helpers/ParameterParser.php`

Parses and validates URL parameters.

**Methods:**
- `parsePlainParams(Request)` - Parse plain SUN parameters
- `parseEncryptedParams(Request)` - Parse encrypted SUN parameters
- `interpretTamperStatus(string)` - Interpret tamper tag file data

#### SDMServiceProvider

**File:** `app/Providers/SDMServiceProvider.php`

Service provider for key derivation and SDM instance creation.

**Provides:**
- `KeyDerivation` singleton
- `sdm.factory` - Factory callable for creating SDM instances

### Key Derivation Flow

```php
// 1. Get master key from config
$masterKey = hex2bin(config('sdm.master_key'));

// 2. Derive undiversified key for PICC data
$kdf = app(KeyDerivation::class);
$encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);

// 3. Create SDM instance
$sdm = new SDM($encKey, '');

// 4. Decrypt with dynamic MAC key derivation
$result = $sdm->decryptSunMessage(
    sdmMetaReadKey: $encKey,
    sdmFileReadKey: function(string $uid) use ($kdf, $masterKey): string {
        // Derive tag-specific key after UID is decrypted
        return $kdf->deriveTagKey($masterKey, $uid, 2);
    },
    // ... other parameters
);
```

### Request Flow

```
Client Request
    ↓
Route (web.php)
    ↓
SDMController
    ↓
ParameterParser (validate & parse)
    ↓
SDM Library (decrypt/validate)
    ↓
Response (HTML or JSON)
```

## WebNFC Interface

The application includes a browser-based NFC scanning interface using the WebNFC API.

**Route:** `GET /webnfc`

**File:** `resources/views/webnfc.blade.php`

### Features

- Real-time NFC tag scanning
- Automatic URL parsing from NDEF records
- Parameter extraction and validation
- Live result display
- Support for all SDM message types

### Browser Support

**Supported:**
- Chrome for Android (version 89+)

**Not Supported:**
- iOS (no WebNFC support)
- Desktop browsers (limited WebNFC support)

### Usage

1. Open `http://localhost:8000/webnfc` on Chrome for Android
2. Click "Scan NFC Tag" button
3. Hold NTAG 424 DNA tag near device
4. View decrypted results

### Security Note

WebNFC requires HTTPS in production. Use `http://localhost` for development only.

## Demo Mode

Demo mode is automatically activated when using factory keys (all zeros).

### Features

- Example URLs displayed on landing page
- Attribution to NXP and nfc-developer
- Sample data for testing
- All functionality works normally

### Activating Demo Mode

```bash
SDM_MASTER_KEY=00000000000000000000000000000000
```

### Detecting Demo Mode

```php
if (config('sdm.is_demo_mode')) {
    // Show example URLs and attribution
}
```

### Production Mode

Set a real master key to disable demo mode:

```bash
SDM_MASTER_KEY=C9EB67DF090AFF47C3B19A2516680B9D
```

## Response Formats

### HTML Response

Returns Blade view with formatted data.

**Success View:** `resources/views/info.blade.php`

**Error View:** `resources/views/error.blade.php`

**Variables:**
- `$encryptionMode` - "AES" or "LRP"
- `$uid` - Binary UID (displayed as hex)
- `$readCtr` - Integer read counter
- `$fileData` - Binary file data (displayed as hex)
- `$fileDataUtf8` - UTF-8 converted file data
- `$tamperStatus` - Tamper status (TagTamper only)
- `$tamperColor` - Color for tamper status (TagTamper only)

### JSON Response

Returns pretty-printed JSON with appropriate HTTP status codes.

**Success (200 OK):**

```json
{
    "picc_data_tag": "c7",
    "encryption_mode": "AES",
    "uid": "041e3c8a2d6b80",
    "read_ctr": 6,
    "file_data": "4343",
    "file_data_utf8": "CC"
}
```

**Validation Error (403 Forbidden):**

```json
{
    "error": "Message is not properly signed - invalid MAC"
}
```

**Decryption Error (400 Bad Request):**

```json
{
    "error": "Invalid encrypted PICC data length - expected 16 bytes (AES) or 24 bytes (LRP), got 8 bytes. This may indicate malformed or truncated input data."
}
```

**Invalid Input (400 Bad Request):**

```json
{
    "error": "Missing required parameter: picc_data"
}
```

**LRP Required (501 Not Implemented):**

```json
{
    "error": "LRP mode is required"
}
```

### Tamper Status Interpretation

**File Data Format:** First 2 bytes indicate tamper status

| Bytes | Status | Color | Description |
|-------|--------|-------|-------------|
| `CC CC` | Secure | Green | Tag has not been tampered with |
| `0C CC` | Tampered (Closed) | Red | Loop was opened and closed |
| `0C 0C` | Tampered (Open) | Red | Loop is currently open |
| `CD CD` | Uninitialized | Orange | TagTamper not initialized |
| Other | Unknown | Gray | Not a TagTamper variant |

**Implementation:**

```php
function interpretTamperStatus(string $fileData): ?array
{
    if (strlen($fileData) < 2) {
        return null;
    }

    $statusBytes = substr($fileData, 0, 2);

    return match ($statusBytes) {
        "\xCC\xCC" => ['status' => 'Secure', 'color' => 'green'],
        "\x0C\xCC" => ['status' => 'Tampered (Closed)', 'color' => 'red'],
        "\x0C\x0C" => ['status' => 'Tampered (Open)', 'color' => 'red'],
        "\xCD\xCD" => ['status' => 'Uninitialized', 'color' => 'orange'],
        default => ['status' => 'Not TagTamper', 'color' => 'orange'],
    };
}
```

## Deployment

### Production Requirements

- PHP 8.3 or higher
- Composer
- Web server (Apache, Nginx, etc.)
- HTTPS (required for WebNFC)
- Environment variables configured

### Step 1: Install Dependencies

```bash
composer install --no-dev --optimize-autoloader
```

### Step 2: Configure Environment

Create `.env` file with production settings:

```bash
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:your_app_key_here

SDM_MASTER_KEY=your_32_character_hex_master_key

# Optional customization
SDM_ENC_PICC_DATA_PARAM=picc_data
SDM_ENC_FILE_DATA_PARAM=enc
SDM_SDMMAC_PARAM=cmac
SDM_REQUIRE_LRP=false
```

### Step 3: Optimize Laravel

```bash
php artisan config:cache
php artisan route:cache
php artisan view:cache
```

### Step 4: Set Permissions

```bash
chmod -R 755 storage bootstrap/cache
```

### Step 5: Configure Web Server

**Nginx Example:**

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    root /path/to/example-app/public;
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        include fastcgi_params;
    }
}
```

### Security Considerations

1. **HTTPS Required** - WebNFC only works over HTTPS
2. **Key Security** - Store master key in environment variables, never in code
3. **Input Validation** - All parameters are validated before processing
4. **CMAC Verification** - Always verify CMAC before trusting decrypted data
5. **Error Messages** - Production errors should not reveal sensitive information

### Monitoring

Log all validation failures for security monitoring:

```php
// In SDMController
catch (ValidationException $e) {
    Log::warning('CMAC validation failed', [
        'uid' => $uid,
        'ip' => $request->ip(),
        'error' => $e->getMessage(),
    ]);
    return $this->jsonErrorResponse($e->getMessage(), 403);
}
```

---

## Testing

Run the included tests:

```bash
php artisan test
```

## References

- [NXP AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf) - NTAG 424 DNA and TagTamper Features
- [NXP AN12304](https://www.nxp.com/docs/en/application-note/AN12304.pdf) - Leakage Resilient Primitive
- [kduma/php-sdm](https://github.com/kduma-autoid/php-sdm) - PHP SDM Library
- [nfc-developer/sdm-backend](https://github.com/nfc-developer/sdm-backend) - Original Python Implementation
- [WebNFC API](https://developer.mozilla.org/en-US/docs/Web/API/Web_NFC_API) - WebNFC Documentation

## License

MIT License. See [LICENSE](../LICENSE) for details.
