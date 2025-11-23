# SDM Backend Server - Laravel Example Application

This Laravel application demonstrates the usage of the [kduma/php-sdm](https://github.com/kduma-autoid/php-sdm) library for processing NTAG 424 DNA Secure Dynamic Messaging (SDM) data.

This implementation is a PHP/Laravel port of the Python Flask [nfc-developer/sdm-backend](https://github.com/nfc-developer/sdm-backend) application.

## Features

- **Plain SUN Message Validation** - Validate plaintext UID with mirrored Read Counter and CMAC
- **Encrypted SUN Message Decryption** - Decrypt and validate encrypted PICC and file data
- **Tamper-Tag Support** - Detect and report tamper status from TagTamper variant tags
- **Dual Output** - HTML views for browsers and JSON API endpoints for programmatic access
- **WebNFC Interface** - Browser-based NFC tag scanning (Chrome for Android only)
- **Demo Mode** - Automatic example data when using factory keys (all zeros)
- **LRP Preparation** - Detection and graceful handling of LRP mode (not yet supported in library)

## Requirements

- PHP 8.3 or higher
- Laravel 12.x
- kduma/php-sdm library

## Installation

1. **Navigate to the example-app directory:**
   ```bash
   cd example-app
   ```

2. **Install dependencies** (already done during creation):
   ```bash
   composer install
   ```

3. **Configure environment:**
   The `.env` file is already configured with demo mode enabled (all-zeros master key).

   To use your own keys, edit `.env` and set:
   ```bash
   SDM_MASTER_KEY=your_hex_master_key_here
   ```

4. **Start the development server:**
   ```bash
   php artisan serve
   ```

5. **Visit the application:**
   Open your browser to `http://localhost:8000`

## Configuration

All SDM-related configuration is in `config/sdm.php` and can be overridden via `.env`:

### Master Key

```bash
SDM_MASTER_KEY=00000000000000000000000000000000
```

- **32-character hexadecimal string** (16 bytes)
- **Demo Mode:** When set to all zeros, the application shows example URLs and GitHub attribution
- **Production:** Use your actual master key derived from your NTAG 424 DNA tag configuration

### Parameter Names

Customize the URL parameter names used in SDM URLs:

```bash
SDM_ENC_PICC_DATA_PARAM=picc_data
SDM_ENC_FILE_DATA_PARAM=enc
SDM_UID_PARAM=uid
SDM_CTR_PARAM=ctr
SDM_SDMMAC_PARAM=cmac
```

### LRP Mode (Future Feature)

```bash
SDM_REQUIRE_LRP=false
```

When enabled, the application will enforce LRP encryption mode and reject AES requests.
**Note:** LRP mode is not yet implemented in the php-sdm library.

## Routes

### Web Routes (HTML Output)

| Route | Description |
|-------|-------------|
| `GET /` | Main landing page with example URLs |
| `GET /tagpt` | Plain SUN message validation |
| `GET /tag` | SUN message decryption |
| `GET /tagtt` | Tamper-tag SUN message decryption |
| `GET /webnfc` | WebNFC interface for browser-based scanning |

### API Routes (JSON Output)

| Route | Description |
|-------|-------------|
| `GET /api/tagpt` | Plain SUN validation (JSON) |
| `GET /api/tag` | SUN decryption (JSON) |
| `GET /api/tagtt` | Tamper-tag decryption (JSON) |

## Usage Examples

### Plain SUN Validation

```bash
# HTML output
curl "http://localhost:8000/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3"

# JSON output
curl "http://localhost:8000/api/tagpt?uid=041E3C8A2D6B80&ctr=000006&cmac=4B00064004B0B3D3"
```

### Encrypted SUN Message (AES)

```bash
# HTML output
curl "http://localhost:8000/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"

# JSON output
curl "http://localhost:8000/api/tag?picc_data=EF963FF7828658A599F3041510671E88&cmac=94EED9EE65337086"
```

### Encrypted with File Data

```bash
curl "http://localhost:8000/tag?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6"
```

### Tamper-Tag Variant

```bash
curl "http://localhost:8000/tagtt?picc_data=FDD387BF32A33A7C40CF259675B3A1E2&enc=EA050C282D8E9043E28F7A171464D697&cmac=758110182134ECE9"
```

## JSON Response Format

All API endpoints return prettified JSON:

```json
{
  "picc_data_tag": "c7",
  "encryption_mode": "AES",
  "uid": "041e3c8a2d6b80",
  "read_ctr": 6,
  "file_data": "4343",
  "file_data_utf8": "CC",
  "tamper_status": "Secure"
}
```

## Architecture

### Key Components

- **`config/sdm.php`** - Configuration file with demo mode detection
- **`app/Providers/SDMServiceProvider.php`** - Service provider for key derivation and SDM instances
- **`app/Helpers/ParameterParser.php`** - Parameter parsing (bulk vs separated modes)
- **`app/Http/Controllers/SDMController.php`** - All route handlers
- **`resources/views/`** - Blade templates (layout, main, info, webnfc, error)

### Key Derivation

The application uses two-level key derivation:

1. **Undiversified Key** - Derived from master key for PICC data decryption
2. **Tag-Specific Key** - Derived from master key + UID for file data and CMAC

```php
$masterKey = hex2bin(config('sdm.master_key'));
$kdf = new KeyDerivation();

// For PICC data encryption
$encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);

// For file data and CMAC (per-tag)
$macKey = $kdf->deriveTagKey($masterKey, $uid, 2);
```

### Tamper Status Interpretation

The application interprets the first 2 bytes of file data as tamper status:

| Bytes | Status | Color |
|-------|--------|-------|
| `CC` | Secure | Green |
| `OC` | Tampered (Closed) | Red |
| `OO` | Tampered (Open) | Red |
| `II` | Uninitialized | Orange |
| `NT` | Not TagTamper | Orange |

## Development

### Running Tests

```bash
php artisan test
```

### Code Style

```bash
composer cs-fix
```

### Static Analysis

```bash
composer phpstan
```

## References

- [NXP AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf) - NTAG 424 DNA and TagTamper Features
- [kduma/php-sdm](https://github.com/kduma-autoid/php-sdm) - PHP SDM Library
- [nfc-developer/sdm-backend](https://github.com/nfc-developer/sdm-backend) - Original Python Implementation

## License

MIT License. See [LICENSE](../LICENSE) for details.
