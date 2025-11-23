# PHP SDM - NTAG 424 DNA Implementation

A PHP library for decrypting and validating NTAG 424 DNA Secure Dynamic Messaging (SDM) data.

[![PHP Version](https://img.shields.io/badge/php-%5E8.3-blue)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Features

- **NTAG 424 DNA SDM** support with AES and LRP encryption modes
- **CMAC validation** for message authentication
- **Key derivation** with UID diversification (NIST SP 800-108)
- **Plain and encrypted SUN messages**
- **Tamper detection** support for TagTamper variant
- **Example Laravel app** included

## Installation

```bash
composer require kduma/php-sdm
```

## Quick Start

```php
use KDuma\SDM\SDM;
use KDuma\SDM\KeyDerivation;

// Initialize with your keys
$masterKey = hex2bin('your_master_key_here');
$kdf = new KeyDerivation();

// Derive encryption and MAC keys
$encKey = $kdf->deriveUndiversifiedKey($masterKey, 1);
$macKey = $kdf->deriveTagKey($masterKey, $uid, 2);

$sdm = new SDM($encKey, $macKey);

// Decrypt SDM message
$result = $sdm->decrypt(
    encData: hex2bin($piccData),
    encFileData: hex2bin($encFileData),
    cmac: hex2bin($cmac)
);

// Or validate plain SUN message
$isValid = $sdm->validate(
    data: hex2bin($uid . $readCtr),
    cmac: hex2bin($cmac)
);
```

## Documentation

- **[Documentation](DOCUMENTATION.md)** - Detailed usage guide and examples
- **[API Reference](API.md)** - Complete API documentation
- **[Example App](EXAMPLE_APP.md)** - Laravel example application guide

## Requirements

- PHP 8.3 or higher
- OpenSSL extension (for AES operations)

## Example Application

The library includes a full Laravel application demonstrating real-world usage:

```bash
cd example-app
composer install
php artisan serve
```

Visit `http://localhost:8000` for a working demo with WebNFC support.

See [EXAMPLE_APP.md](EXAMPLE_APP.md) for details.

## Development

```bash
# Install dependencies
composer install

# Run tests
composer test

# Run static analysis
composer phpstan

# Fix code style
composer cs-fix
```

## References

- [NXP AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf) - NTAG 424 DNA and TagTamper Features
- [NXP AN12304](https://www.nxp.com/docs/en/application-note/AN12304.pdf) - Leakage Resilient Primitive (LRP)
- [NIST SP 800-108](https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final) - Key Derivation Functions

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
