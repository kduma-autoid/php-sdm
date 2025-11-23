# Contributing to PHP SDM

Thank you for your interest in contributing to the PHP SDM library!

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/kduma-autoid/php-sdm.git
cd php-sdm
```

2. Install dependencies:
```bash
composer install
```

3. Run tests:
```bash
composer test
```

## Code Standards

This project follows:
- PSR-12 coding standard
- PHPStan level max static analysis
- PHP 8.3+ features and type hints

Before submitting a PR, ensure:

```bash
# Run tests
composer test

# Run static analysis
composer phpstan

# Check code style
composer cs-check

# Fix code style automatically
composer cs-fix
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Write or update tests
5. Ensure all tests pass
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Commit Message Guidelines

- Use clear and meaningful commit messages
- Start with a verb in present tense (Add, Update, Fix, Remove)
- Keep the first line under 72 characters
- Add detailed description if needed

## Testing

- Write PHPUnit tests for new features
- Ensure existing tests pass
- Aim for high code coverage
- Test edge cases and error conditions

## Code Review

All submissions require review. We use GitHub pull requests for this purpose.

## Questions?

Feel free to open an issue for:
- Bug reports
- Feature requests
- Questions about implementation
- Documentation improvements

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
