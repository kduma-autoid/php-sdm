# API Reference

Complete API documentation for the PHP SDM library.

## Table of Contents

- [SDM Class](#sdm-class)
- [KeyDerivation Class](#keyderivation-class)
- [Enums](#enums)
- [Exceptions](#exceptions)
- [Cipher Classes](#cipher-classes)

---

## SDM Class

**Namespace:** `KDuma\SDM`

**Implements:** `SDMInterface`

Main class for NTAG 424 DNA Secure Dynamic Messaging operations.

### Constructor

```php
public function __construct(
    string $encKey,
    string $macKey,
    string $sdmmacParam = ''
)
```

Creates a new SDM instance.

**Parameters:**
- `$encKey` - Encryption key for PICC data (binary, 16 bytes)
- `$macKey` - MAC calculation key (binary, 16 bytes)
- `$sdmmacParam` - SDMMAC parameter name for separated mode (default: empty string)

**Example:**

```php
$sdm = new SDM(
    encKey: hex2bin('C9EB67DF090AFF47C3B19A2516680B9D'),
    macKey: hex2bin('1234567890ABCDEF1234567890ABCDEF'),
    sdmmacParam: 'cmac'
);
```

---

### decrypt()

```php
public function decrypt(
    string $encData,
    string $encFileData,
    string $cmac
): array
```

Decrypt and validate an SDM message (convenience wrapper).

**Parameters:**
- `$encData` - Encrypted PICC data (binary, 16 or 24 bytes)
- `$encFileData` - Encrypted file data (binary, multiple of 16 bytes, or empty)
- `$cmac` - CMAC for authentication (binary, 8 bytes)

**Returns:** Array with decrypted data:
```php
[
    'picc_data_tag' => string,      // 1 byte: PICCDataTag configuration
    'uid' => string,                 // 7 bytes: Tag UID
    'read_ctr' => int,              // Read counter value (0-16777215)
    'file_data' => ?string,         // Decrypted file data or null
    'encryption_mode' => EncMode    // AES or LRP
]
```

**Throws:**
- `DecryptionException` - If decryption fails
- `ValidationException` - If CMAC validation fails

**Example:**

```php
$result = $sdm->decrypt(
    encData: hex2bin('EF963FF7828658A599F3041510671E88'),
    encFileData: hex2bin('CEE9A53E3E463EF1F459635736738962'),
    cmac: hex2bin('94EED9EE65337086')
);

echo "UID: " . bin2hex($result['uid']) . "\n";
echo "Counter: " . $result['read_ctr'] . "\n";
```

---

### validate()

```php
public function validate(string $data, string $cmac): bool
```

Validate plain SUN message authentication (convenience wrapper).

**Parameters:**
- `$data` - Plain SUN data: UID (7 bytes) + ReadCtr (3 bytes), exactly 10 bytes
- `$cmac` - SDMMAC to validate against (binary, 8 bytes)

**Returns:** `true` if valid, `false` otherwise

**Example:**

```php
$data = hex2bin('041E3C8A2D6B80000006'); // UID + counter
$cmac = hex2bin('4B00064004B0B3D3');

if ($sdm->validate($data, $cmac)) {
    echo "Valid SUN message";
}
```

**Note:** This method assumes AES mode. For LRP mode or detailed results, use `validatePlainSun()`.

---

### decryptSunMessage()

```php
public function decryptSunMessage(
    ParamMode $paramMode,
    string $sdmMetaReadKey,
    callable $sdmFileReadKey,
    string $piccEncData,
    string $sdmmac,
    ?string $encFileData = null
): array
```

Decrypt SUN message for NTAG 424 DNA (advanced method).

**Parameters:**
- `$paramMode` - Type of dynamic URL encoding (SEPARATED or BULK)
- `$sdmMetaReadKey` - SUN decryption key for PICC data (binary, 16 bytes)
- `$sdmFileReadKey` - Callable that returns MAC key: `function(string $uid): string`
- `$piccEncData` - Encrypted PICC data (binary, 16 or 24 bytes)
- `$sdmmac` - SDMMAC of the SUN message (binary, 8 bytes)
- `$encFileData` - Optional encrypted file data (binary, multiple of 16 bytes)

**Returns:** Array with decrypted data (same as `decrypt()`)

**Throws:**
- `DecryptionException` - If SUN message is invalid
- `ValidationException` - If MAC is invalid

**Example:**

```php
use KDuma\SDM\ParamMode;

$result = $sdm->decryptSunMessage(
    paramMode: ParamMode::SEPARATED,
    sdmMetaReadKey: $encKey,
    sdmFileReadKey: function(string $uid) use ($kdf, $masterKey): string {
        return $kdf->deriveTagKey($masterKey, $uid, 2);
    },
    piccEncData: hex2bin($piccData),
    sdmmac: hex2bin($cmac),
    encFileData: hex2bin($encFileData)
);
```

---

### validatePlainSun()

```php
public function validatePlainSun(
    string $uid,
    string $readCtr,
    string $sdmmac,
    string $sdmFileReadKey,
    ?EncMode $mode = null
): array
```

Validate plain (unencrypted) SUN message authentication.

**Parameters:**
- `$uid` - Tag's unique identifier (binary, 7 bytes)
- `$readCtr` - SDM read counter (binary, 3 bytes, little-endian)
- `$sdmmac` - SDMMAC to validate against (binary, 8 bytes)
- `$sdmFileReadKey` - MAC calculation key (binary, 16 bytes)
- `$mode` - Encryption mode (EncMode::AES or EncMode::LRP, default: AES)

**Returns:** Array with validation result:
```php
[
    'encryption_mode' => EncMode,  // AES or LRP
    'uid' => string,                // 7 bytes: Tag UID
    'read_ctr' => int              // Read counter value
]
```

**Throws:**
- `ValidationException` - If MAC is invalid or input data is malformed

**Example:**

```php
use KDuma\SDM\EncMode;

$result = $sdm->validatePlainSun(
    uid: hex2bin('041E3C8A2D6B80'),
    readCtr: hex2bin('000006'),
    sdmmac: hex2bin('4B00064004B0B3D3'),
    sdmFileReadKey: $macKey,
    mode: EncMode::AES
);
```

---

### calculateSdmmac()

```php
public function calculateSdmmac(
    ParamMode $paramMode,
    string $sdmFileReadKey,
    string $piccData,
    ?string $encFileData = null,
    ?EncMode $mode = null
): string
```

Calculate SDMMAC for NTAG 424 DNA.

**Parameters:**
- `$paramMode` - Type of dynamic URL encoding (SEPARATED or BULK)
- `$sdmFileReadKey` - MAC calculation key (binary, 16 bytes)
- `$piccData` - UID + SDMReadCtr (binary, 10 bytes)
- `$encFileData` - Optional encrypted file data (binary)
- `$mode` - Encryption mode (EncMode::AES or EncMode::LRP, default: AES)

**Returns:** Calculated SDMMAC (binary, 8 bytes)

**Example:**

```php
use KDuma\SDM\ParamMode;
use KDuma\SDM\EncMode;

$piccData = $uid . strrev($readCtr); // UID + reversed counter
$sdmmac = $sdm->calculateSdmmac(
    paramMode: ParamMode::SEPARATED,
    sdmFileReadKey: $macKey,
    piccData: $piccData,
    encFileData: $encFileData,
    mode: EncMode::AES
);
```

---

### decryptFileData()

```php
public function decryptFileData(
    string $sdmFileReadKey,
    string $piccData,
    string $readCtr,
    string $encFileData,
    ?EncMode $mode = null
): string
```

Decrypt SDMEncFileData for NTAG 424 DNA.

**Parameters:**
- `$sdmFileReadKey` - SUN decryption key (binary, 16 bytes)
- `$piccData` - PICCDataTag + UID + SDMReadCtr (binary)
- `$readCtr` - SDM read counter (binary, 3 bytes, little-endian)
- `$encFileData` - Encrypted file data (binary, multiple of 16 bytes)
- `$mode` - Encryption mode (EncMode::AES or EncMode::LRP, default: AES)

**Returns:** Decrypted file data (binary)

**Example:**

```php
use KDuma\SDM\EncMode;

$fileData = $sdm->decryptFileData(
    sdmFileReadKey: $fileKey,
    piccData: $uid . strrev($readCtr),
    readCtr: $readCtr,
    encFileData: $encryptedData,
    mode: EncMode::AES
);
```

---

### getEncryptionMode()

```php
public function getEncryptionMode(string $piccEncData): EncMode
```

Get encryption mode from PICC encrypted data length.

**Parameters:**
- `$piccEncData` - Encrypted PICC data (binary)

**Returns:** Detected encryption mode (EncMode::AES or EncMode::LRP)

**Throws:**
- `DecryptionException` - If unsupported encryption mode (not 16 or 24 bytes)

**Example:**

```php
$mode = $sdm->getEncryptionMode($piccEncData);

if ($mode === EncMode::AES) {
    echo "Using AES mode";
} else {
    echo "Using LRP mode";
}
```

---

## KeyDerivation Class

**Namespace:** `KDuma\SDM`

Key derivation functions for NTAG 424 DNA based on NIST SP 800-108.

### Constructor

```php
public function __construct()
```

Creates a new KeyDerivation instance.

**Example:**

```php
$kdf = new KeyDerivation();
```

---

### deriveUndiversifiedKey()

```php
public function deriveUndiversifiedKey(
    string $masterKey,
    int $keyNumber
): string
```

Derive an undiversified key from a master key.

**Parameters:**
- `$masterKey` - Master key (binary, 16-32 bytes)
- `$keyNumber` - Key number (must be 1)

**Returns:** Derived key (binary, 16 bytes)

**Throws:**
- `InvalidArgumentException` - If key number is not 1 or master key length is invalid

**Example:**

```php
$masterKey = hex2bin('C9EB67DF090AFF47C3B19A2516680B9D');
$encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);
```

**Note:** Returns factory key unchanged if master key is all zeros.

---

### deriveTagKey()

```php
public function deriveTagKey(
    string $masterKey,
    string $uid,
    int $keyNumber
): string
```

Derive a tag-specific (UID-diversified) key from a master key.

**Parameters:**
- `$masterKey` - Master key (binary, 16-32 bytes)
- `$uid` - UID of the tag (binary, exactly 7 bytes)
- `$keyNumber` - Key number (1 or 2)

**Returns:** Derived key (binary, 16 bytes)

**Throws:**
- `InvalidArgumentException` - If UID length is not 7 bytes, key number is invalid, or master key length is invalid

**Example:**

```php
$uid = hex2bin('04E12AB3CD5E80');
$fileKey = $kdf->deriveTagKey($masterKey, $uid, 1); // File read key
$macKey = $kdf->deriveTagKey($masterKey, $uid, 2);  // MAC key
```

**Key Numbers:**
- `1` - File read key (K_SDMFileReadKey)
- `2` - MAC key (K_SDMFileReadMACKey)

**Note:** Returns factory key unchanged if master key is all zeros.

---

## Enums

### EncMode

**Namespace:** `KDuma\SDM`

Encryption mode for NTAG 424 DNA SDM.

**Values:**

```php
enum EncMode: int
{
    case AES = 0;  // AES-128 mode (16-byte PICC data)
    case LRP = 1;  // Leakage Resilient Primitive (24-byte PICC data)
}
```

**Usage:**

```php
use KDuma\SDM\EncMode;

$mode = EncMode::AES;
echo $mode->name;  // "AES"
echo $mode->value; // 0

if ($mode === EncMode::AES) {
    // Handle AES mode
}
```

---

### ParamMode

**Namespace:** `KDuma\SDM`

Parameter mode for dynamic URL encoding.

**Values:**

```php
enum ParamMode: int
{
    case SEPARATED = 0;  // Each parameter has its own name
    case BULK = 1;       // All parameters concatenated
}
```

**Usage:**

```php
use KDuma\SDM\ParamMode;

$mode = ParamMode::SEPARATED;
echo $mode->name;  // "SEPARATED"
echo $mode->value; // 0
```

**Examples:**

- **SEPARATED:** `?picc_data=xxx&enc=yyy&cmac=zzz`
- **BULK:** `?data=xxxyyyzzz`

---

## Exceptions

All exceptions extend from the base `SDMException` class.

### SDMException

**Namespace:** `KDuma\SDM\Exceptions`

Base exception for all SDM-related errors.

```php
class SDMException extends \Exception
{
}
```

---

### DecryptionException

**Namespace:** `KDuma\SDM\Exceptions`

Thrown when decryption fails.

```php
class DecryptionException extends SDMException
{
}
```

**Common scenarios:**
- Invalid encryption key
- Malformed encrypted data
- Incorrect data length
- Unsupported encryption mode
- Failed to decrypt PICC data

**Example:**

```php
use KDuma\SDM\Exceptions\DecryptionException;

try {
    $result = $sdm->decrypt($encData, $encFileData, $cmac);
} catch (DecryptionException $e) {
    error_log("Decryption failed: " . $e->getMessage());
}
```

---

### ValidationException

**Namespace:** `KDuma\SDM\Exceptions`

Thrown when CMAC validation fails.

```php
class ValidationException extends SDMException
{
}
```

**Common scenarios:**
- Invalid CMAC
- Tampered data
- Wrong MAC key
- Incorrect parameter mode

**Example:**

```php
use KDuma\SDM\Exceptions\ValidationException;

try {
    $result = $sdm->decrypt($encData, $encFileData, $cmac);
} catch (ValidationException $e) {
    error_log("Validation failed - possible tampering: " . $e->getMessage());
}
```

---

## Cipher Classes

Internal cipher implementations (not typically used directly).

### AESCipher

**Namespace:** `KDuma\SDM\Cipher`

**Implements:** `CipherInterface`

AES-128 cipher implementation for SDM operations.

#### encrypt()

```php
public function encrypt(
    string $data,
    string $key,
    string $iv
): string
```

Encrypt data using AES-128-CBC.

**Parameters:**
- `$data` - Data to encrypt (binary)
- `$key` - Encryption key (binary, 16 bytes)
- `$iv` - Initialization vector (binary, 16 bytes)

**Returns:** Encrypted data (binary)

---

#### decrypt()

```php
public function decrypt(
    string $data,
    string $key,
    string $iv
): string
```

Decrypt data using AES-128-CBC.

**Parameters:**
- `$data` - Data to decrypt (binary)
- `$key` - Decryption key (binary, 16 bytes)
- `$iv` - Initialization vector (binary, 16 bytes)

**Returns:** Decrypted data (binary)

---

#### cmac()

```php
public function cmac(
    string $data,
    string $key
): string
```

Calculate AES-CMAC (RFC 4493).

**Parameters:**
- `$data` - Data to authenticate (binary or string)
- `$key` - CMAC key (binary, 16 bytes)

**Returns:** CMAC value (binary, 16 bytes)

**Note:** The `$key` parameter is ignored when using OpenSSL implementation. The key from constructor or first call is used.

---

#### encryptECB()

```php
public function encryptECB(
    string $data,
    string $key
): string
```

Encrypt data using AES-128-ECB (no IV).

**Parameters:**
- `$data` - Data to encrypt (binary, must be multiple of 16 bytes)
- `$key` - Encryption key (binary, 16 bytes)

**Returns:** Encrypted data (binary)

---

### LRPCipher

**Namespace:** `KDuma\SDM\Cipher`

**Implements:** `CipherInterface`

Leakage Resilient Primitive cipher implementation.

#### Constructor

```php
public function __construct(
    string $key,
    int $updateMode,
    ?string $counter = null,
    bool $padCounter = true
)
```

**Parameters:**
- `$key` - LRP key (binary, 16 bytes)
- `$updateMode` - Update mode (0 for CMAC, 1 for encryption)
- `$counter` - Optional counter/IV (binary, 1-16 bytes)
- `$padCounter` - Whether to pad counter to 16 bytes (default: true)

---

#### encrypt()

```php
public function encrypt(
    string $data,
    string $key,
    string $iv
): string
```

Encrypt data using LRP.

**Parameters:**
- `$data` - Data to encrypt (binary)
- `$key` - Encryption key (binary, 16 bytes)
- `$iv` - Counter/IV (binary, 1-16 bytes)

**Returns:** Encrypted data (binary)

---

#### decrypt()

```php
public function decrypt(
    string $data,
    string $key,
    string $iv
): string
```

Decrypt data using LRP.

**Parameters:**
- `$data` - Data to decrypt (binary)
- `$key` - Decryption key (binary, 16 bytes)
- `$iv` - Counter/IV (binary, 1-16 bytes)

**Returns:** Decrypted data (binary)

---

#### cmac()

```php
public function cmac(
    string $data,
    string $key
): string
```

Calculate LRP CMAC.

**Parameters:**
- `$data` - Data to authenticate (binary or string)
- `$key` - CMAC key (binary, 16 bytes)

**Returns:** CMAC value (binary, 16 bytes)

**Note:** The `$key` parameter is ignored. The key from constructor is used.

---

## Type Definitions

### SDMInterface

```php
interface SDMInterface
{
    public function decrypt(
        string $encData,
        string $encFileData,
        string $cmac
    ): array;

    public function validate(
        string $data,
        string $cmac
    ): bool;
}
```

---

### CipherInterface

```php
interface CipherInterface
{
    public function encrypt(
        string $data,
        string $key,
        string $iv
    ): string;

    public function decrypt(
        string $data,
        string $key,
        string $iv
    ): string;

    public function cmac(
        string $data,
        string $key
    ): string;
}
```

---

## Constants

### SDM Class Constants

Internal constants used for protocol implementation:

```php
// Session vector prefixes
private const SV2_PREFIX_CMAC = "\x3C\xC3\x00\x01\x00\x80";
private const SV1_PREFIX_ENC = "\xC3\x3C\x00\x01\x00\x80";

// LRP protocol
private const LRP_PROTOCOL_PREFIX = "\x00\x01\x00\x80";
private const LRP_STREAM_TRAILER = "\x1E\xE1";

// PICCDataTag bit masks
private const PICC_UID_MIRROR_MASK = 0x80;
private const PICC_READ_CTR_MASK = 0x40;
private const PICC_UID_LENGTH_MASK = 0x0F;
private const PICC_SUPPORTED_UID_LENGTH = 0x07;
```

### KeyDerivation Class Constants

Diversification constants from NTAG 424 DNA specification:

```php
private const DIV_CONST1 = '50494343446174614b6579';     // "PICCDataKey"
private const DIV_CONST2 = '536c6f744d61737465724b6579'; // "SlotMasterKey"
private const DIV_CONST3 = '446976426173654b6579';       // "DivBaseKey"
```

---

## Data Formats

### Binary Data

All binary data in the API uses PHP binary strings (8-bit clean strings).

**Converting hex to binary:**

```php
$binary = hex2bin('041E3C8A2D6B80');
```

**Converting binary to hex:**

```php
$hex = bin2hex($binary);
```

### Read Counter Format

**In encrypted PICC data:** 3 bytes, little-endian

```php
$readCtr = "\x06\x00\x00"; // Counter value 6
```

**In return values:** Integer (0-16777215)

```php
$result['read_ctr']; // 6
```

### UID Format

**Always 7 bytes for NTAG 424 DNA:**

```php
$uid = hex2bin('041E3C8A2D6B80'); // 7 bytes
```

### CMAC Format

**Always 8 bytes:**

```php
$cmac = hex2bin('94EED9EE65337086'); // 8 bytes
```

### Encrypted Data Lengths

**PICC encrypted data:**
- AES mode: 16 bytes
- LRP mode: 24 bytes (8-byte random + 16-byte encrypted)

**File encrypted data:**
- Multiple of 16 bytes (AES block size)
- Can be empty (null)

---

For usage examples, see [DOCUMENTATION.md](DOCUMENTATION.md).

For the example application, see [EXAMPLE_APP.md](EXAMPLE_APP.md).
