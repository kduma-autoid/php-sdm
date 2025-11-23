#!/usr/bin/env python3
"""Test Python AES-ECB to verify what it actually produces."""

from Crypto.Cipher import AES
import binascii

# Test the exact same operation as PHP
key = bytes.fromhex('00000000000000000000000000000000')
data = bytes.fromhex('55555555555555555555555555555555')

print("=== Python AES-ECB Test ===")
print(f"Key:  {key.hex()}")
print(f"Data: {data.hex()}")

cipher = AES.new(key, AES.MODE_ECB)
encrypted = cipher.encrypt(data)

print(f"Encrypted: {encrypted.hex()}")
print()

# Test what PHP produced
php_result = bytes.fromhex('9adae054f63dfaff5ea18e45edf6ea6f')
print(f"PHP produced: {php_result.hex()}")
print()

# Try decrypting PHP's result to see what key it might have used
cipher2 = AES.new(key, AES.MODE_ECB)
try:
    decrypted = cipher2.decrypt(php_result)
    print(f"If we decrypt PHP's result: {decrypted.hex()}")
except Exception as e:
    print(f"Error: {e}")
