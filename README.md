# PHP SDM (Secure Dynamic Messaging) Library

A PHP 8.3+ library for working with NTAG 424 DNA Secure Dynamic Messaging (SDM) feature. This library provides tools to decrypt, validate, and authenticate cryptographically secured NFC tag messages.

## Features

- **AES-128 Decryption**: Decrypt SDM encrypted data from NTAG 424 DNA tags
- **CMAC Validation**: Verify message authenticity using CMAC signatures
- **URL Parameter Parsing**: Parse and extract SDM data from NFC-generated URLs
- **Tap Counter Verification**: Validate tap counter to prevent replay attacks
- **PHP 8.3+ Support**: Modern PHP with type safety and performance

## About NTAG 424 DNA SDM

The NTAG 424 DNA is an NFC tag chip from NXP Semiconductors featuring Secure Dynamic Messaging (SDM). Each tap generates a unique, cryptographically secured message that enables:

- **Anti-counterfeiting**: Verify product authenticity
- **Tamper Detection**: Detect unauthorized access
- **Dynamic Authentication**: Each scan produces unique data
- **Secure Data**: AES-128 encryption with CMAC signature

## Installation

```bash
composer require kduma-autoid/php-sdm
```

## Requirements

- PHP 8.3 or higher
- ext-openssl (for AES encryption)
- ext-mbstring (for string operations)

## Usage

### Basic Example

```php
<?php

use KDuma\SDM\SDMMessage;
use KDuma\SDM\SDMDecryptor;

// Parse SDM message from URL parameters
$message = SDMMessage::fromUrl('https://example.com/tag?picc_data=...&enc=...&cmac=...');

// Decrypt and validate
$decryptor = new SDMDecryptor($encryptionKey, $macKey);
$result = $decryptor->decrypt($message);

if ($result->isValid()) {
    echo "Tag UID: " . $result->getUid() . "\n";
    echo "Tap Counter: " . $result->getTapCounter() . "\n";
    echo "Data: " . $result->getData() . "\n";
} else {
    echo "Invalid or tampered message\n";
}
```

### Advanced Usage

```php
<?php

use KDuma\SDM\SDMMessage;
use KDuma\SDM\SDMDecryptor;
use KDuma\SDM\Exceptions\InvalidSignatureException;

$decryptor = new SDMDecryptor(
    encryptionKey: hex2bin('00000000000000000000000000000000'),
    macKey: hex2bin('00000000000000000000000000000000')
);

try {
    $message = SDMMessage::fromArray([
        'picc_data' => $piccData,
        'enc' => $encryptedData,
        'cmac' => $signature
    ]);
    
    $result = $decryptor->decrypt($message);
    
    // Verify tap counter is incrementing (prevent replay attacks)
    $lastCounter = getLastKnownCounter($result->getUid());
    if ($result->getTapCounter() <= $lastCounter) {
        throw new InvalidSignatureException('Replay attack detected');
    }
    
    // Update counter in database
    updateCounter($result->getUid(), $result->getTapCounter());
    
} catch (InvalidSignatureException $e) {
    // Handle authentication failure
    log('Authentication failed: ' . $e->getMessage());
}
```

## Configuration

### Setting Up NTAG 424 DNA Tags

To use this library, you need to:

1. Configure your NTAG 424 DNA tags with SDM enabled
2. Set encryption and MAC keys
3. Configure the SDM URL template
4. Note the file number and offsets for SDM data

Refer to the [NXP AN12196 Application Note](https://www.nxp.com/docs/en/application-note/AN12196.pdf) for detailed setup instructions.

## API Documentation

### Classes

#### `SDMMessage`
Represents a Secure Dynamic Messaging message with encrypted data and signature.

#### `SDMDecryptor`
Handles decryption and validation of SDM messages.

#### `SDMResult`
Contains the decrypted and validated data from an SDM message.

#### Exceptions
- `InvalidMessageException`: Malformed SDM message
- `InvalidSignatureException`: CMAC verification failed
- `DecryptionException`: Unable to decrypt data

## Security Considerations

- **Keep Keys Secret**: Never commit encryption or MAC keys to version control
- **Verify Tap Counter**: Always check that tap counter is incrementing
- **Use HTTPS**: Transmit SDM URLs over secure connections
- **Validate Input**: Sanitize all input data before processing
- **Rate Limiting**: Implement rate limiting to prevent brute force attacks

## Testing

```bash
# Run tests
composer test

# Run tests with coverage
composer test-coverage

# Run static analysis
composer phpstan

# Check code style
composer cs-check

# Fix code style
composer cs-fix
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This library is open-sourced software licensed under the [MIT license](LICENSE).

## Resources

- [NTAG 424 DNA Product Page](https://www.nxp.com/products/rfid-nfc/nfc-hf/ntag-for-tags-and-labels/ntag-424-dna-424-dna-tagtamper-advanced-security-and-privacy-for-trusted-iot-applications:NTAG424DNA)
- [AN12196 Application Note](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
- [NTAG 424 DNA Datasheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)
- [SDM Feature Overview](https://github.com/AndroidCrypto/Ntag424SdmFeature)

## Credits

Developed by Krystian Duma for AutoID solutions.

## Support

For issues, questions, or contributions, please use the [GitHub issue tracker](https://github.com/kduma-autoid/php-sdm/issues).