# PHP SDM - NTAG DNA 424 Implementation

PHP implementation for NTAG DNA 424 Secure Dynamic Messaging (SDM).

## Features

- NTAG DNA 424 SDM message decryption
- CMAC validation
- AES encryption/decryption
- PICC data parsing
- SUN message handling

## Requirements

- PHP 8.3 or higher

## Installation

```bash
composer require kduma/php-sdm
```

## Usage

```php
use KDuma\SDM\SDM;

// Initialize with your keys
$sdm = new SDM(
    encKey: 'your_encryption_key',
    macKey: 'your_mac_key'
);

// Decrypt SDM message
$result = $sdm->decrypt($encData, $encFileData, $cmac);

// Validate CMAC
$isValid = $sdm->validate($data, $cmac);
```

## Development

### Install dependencies

```bash
composer install
```

### Run tests

```bash
composer test
```

### Run static analysis

```bash
composer phpstan
```

### Fix code style

```bash
composer cs-fix
```

## Structure

```
src/
├── Cipher/          # Cryptographic operations
│   ├── BinaryStringOperations.php
│   ├── CipherInterface.php
│   ├── AESCipher.php
│   └── LRPCipher.php
├── Exceptions/      # Custom exceptions
│   ├── SDMException.php
│   ├── DecryptionException.php
│   └── ValidationException.php
├── EncMode.php      # Encryption mode enum (AES, LRP)
├── ParamMode.php    # Parameter mode enum (SEPARATED, BULK)
├── KeyDerivation.php
├── SDMInterface.php
└── SDM.php
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
