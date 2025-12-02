#!/usr/bin/env python3
"""
ITX Security Shield - License Encryption/Decryption

Handles AES-256-GCM encryption for production.lic files.
"""

import os
import json
import zlib
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .license_format import (
    LicenseData,
    MAGIC_BYTES,
    LICENSE_VERSION,
    ENCRYPTION_TYPE,
    HEADER_SIZE,
    FOOTER_SIZE,
    IV_SIZE,
    AUTH_TAG_SIZE,
)


# ============================================================================
# Encryption Key Management
# ============================================================================

# Master passphrase (should be kept secret!)
# In production, this should be stored securely (env var, HSM, etc.)
MASTER_PASSPHRASE = b"ITX_SECURITY_SHIELD_MASTER_KEY_2024"

# Salt for key derivation (fixed, but could be per-license)
SALT = b"itx_license_salt_v1"


def derive_key(passphrase: bytes = MASTER_PASSPHRASE, salt: bytes = SALT) -> bytes:
    """
    Derive 256-bit encryption key from passphrase using PBKDF2.

    Args:
        passphrase: Master passphrase
        salt: Salt for key derivation

    Returns:
        32-byte AES-256 key
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # OWASP recommended minimum
    )
    return kdf.derive(passphrase)


# ============================================================================
# Encryption Functions
# ============================================================================

def encrypt_license(license_data: LicenseData, passphrase: bytes = MASTER_PASSPHRASE) -> bytes:
    """
    Encrypt license data to binary format.

    File Structure:
        Header (64 bytes):
            - Magic: "ODLI" (4 bytes)
            - Version: 1.0 (4 bytes)
            - Encryption: "AES256GCM" (12 bytes)
            - Reserved (44 bytes)

        Encrypted Data:
            - IV (12 bytes)
            - Ciphertext (variable)
            - Auth Tag (16 bytes)

        Footer (32 bytes):
            - SHA-256 checksum (32 bytes)

    Args:
        license_data: LicenseData object
        passphrase: Encryption passphrase

    Returns:
        Encrypted binary data
    """
    # Derive encryption key
    key = derive_key(passphrase)

    # Convert license to JSON and compress
    json_data = license_data.to_json().encode('utf-8')
    compressed_data = zlib.compress(json_data, level=9)

    # Generate random IV
    iv = os.urandom(IV_SIZE)

    # Encrypt with AES-256-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, compressed_data, None)

    # Build file structure
    header = bytearray(HEADER_SIZE)
    header[0:4] = MAGIC_BYTES
    header[4:8] = LICENSE_VERSION
    header[8:20] = ENCRYPTION_TYPE

    # Encrypted data section
    encrypted_section = iv + ciphertext

    # Calculate footer checksum (SHA-256 of header + encrypted data)
    checksum_data = bytes(header) + encrypted_section
    footer = hashlib.sha256(checksum_data).digest()

    # Combine all sections
    return bytes(header) + encrypted_section + footer


def decrypt_license(encrypted_data: bytes, passphrase: bytes = MASTER_PASSPHRASE) -> LicenseData:
    """
    Decrypt license data from binary format.

    Args:
        encrypted_data: Encrypted binary data
        passphrase: Decryption passphrase

    Returns:
        LicenseData object

    Raises:
        ValueError: If file format is invalid or decryption fails
    """
    # Validate minimum size
    # Note: AUTH_TAG_SIZE is included in ciphertext from aesgcm.encrypt()
    min_size = HEADER_SIZE + IV_SIZE + 16 + FOOTER_SIZE  # IV + minimal ciphertext with tag + footer
    if len(encrypted_data) < min_size:
        raise ValueError(f"Invalid license file: too small (expected >= {min_size} bytes)")

    # Extract sections
    header = encrypted_data[:HEADER_SIZE]
    footer = encrypted_data[-FOOTER_SIZE:]
    encrypted_section = encrypted_data[HEADER_SIZE:-FOOTER_SIZE]

    # Validate header
    if header[0:4] != MAGIC_BYTES:
        raise ValueError("Invalid license file: wrong magic bytes")

    # Validate checksum
    checksum_data = header + encrypted_section
    expected_checksum = hashlib.sha256(checksum_data).digest()
    if footer != expected_checksum:
        raise ValueError("Invalid license file: checksum mismatch (file may be corrupted or tampered)")

    # Extract IV and ciphertext
    iv = encrypted_section[:IV_SIZE]
    ciphertext = encrypted_section[IV_SIZE:]

    # Decrypt with AES-256-GCM
    try:
        key = derive_key(passphrase)
        aesgcm = AESGCM(key)
        compressed_data = aesgcm.decrypt(iv, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e

    # Decompress
    try:
        json_data = zlib.decompress(compressed_data)
    except Exception as e:
        raise ValueError(f"Decompression failed: {e}") from e

    # Parse JSON
    try:
        license_dict = json.loads(json_data.decode('utf-8'))
        return LicenseData.from_dict(license_dict)
    except Exception as e:
        raise ValueError(f"JSON parsing failed: {e}") from e


# ============================================================================
# File I/O Functions
# ============================================================================

def save_license_file(license_data: LicenseData, output_path: str, passphrase: bytes = MASTER_PASSPHRASE) -> None:
    """
    Encrypt and save license to file.

    Args:
        license_data: LicenseData object
        output_path: Path to save production.lic
        passphrase: Encryption passphrase
    """
    encrypted_data = encrypt_license(license_data, passphrase)

    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    print(f"✓ License file saved: {output_path}")
    print(f"  Size: {len(encrypted_data)} bytes")


def load_license_file(license_path: str, passphrase: bytes = MASTER_PASSPHRASE) -> LicenseData:
    """
    Load and decrypt license from file.

    Args:
        license_path: Path to production.lic
        passphrase: Decryption passphrase

    Returns:
        LicenseData object

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If decryption fails
    """
    if not os.path.exists(license_path):
        raise FileNotFoundError(f"License file not found: {license_path}")

    with open(license_path, 'rb') as f:
        encrypted_data = f.read()

    return decrypt_license(encrypted_data, passphrase)


# ============================================================================
# Validation Functions
# ============================================================================

def validate_license_file(license_path: str) -> Tuple[bool, str]:
    """
    Validate license file integrity without full decryption.

    Args:
        license_path: Path to production.lic

    Returns:
        Tuple of (valid, message)
    """
    try:
        if not os.path.exists(license_path):
            return False, f"File not found: {license_path}"

        with open(license_path, 'rb') as f:
            data = f.read()

        # Check minimum size
        min_size = HEADER_SIZE + IV_SIZE + AUTH_TAG_SIZE + FOOTER_SIZE
        if len(data) < min_size:
            return False, f"File too small (expected >= {min_size} bytes)"

        # Check magic bytes
        if data[0:4] != MAGIC_BYTES:
            return False, "Invalid magic bytes (not a valid license file)"

        # Check checksum
        header = data[:HEADER_SIZE]
        footer = data[-FOOTER_SIZE:]
        encrypted_section = data[HEADER_SIZE:-FOOTER_SIZE]

        checksum_data = header + encrypted_section
        expected_checksum = hashlib.sha256(checksum_data).digest()

        if footer != expected_checksum:
            return False, "Checksum mismatch (file corrupted or tampered)"

        return True, "File structure valid"

    except Exception as e:
        return False, f"Validation error: {e}"


# ============================================================================
# Test/Debug Functions
# ============================================================================

def test_encryption():
    """Test encryption/decryption roundtrip."""
    from .license_format import LicenseData

    print("=" * 70)
    print("Testing License Encryption/Decryption")
    print("=" * 70)

    # Create test license
    license_data = LicenseData(
        customer_name="Test Customer",
        po_number="PO-TEST-001",
        licensed_addons=["itx_helloworld"],
        max_instances=1,
        issue_date="2024-12-02",
        expiry_date="2025-12-31",
    )

    print("\n1. Original License Data:")
    print(license_data.to_json())

    # Encrypt
    print("\n2. Encrypting...")
    encrypted = encrypt_license(license_data)
    print(f"   Encrypted size: {len(encrypted)} bytes")
    print(f"   Header: {encrypted[:20].hex()}...")

    # Decrypt
    print("\n3. Decrypting...")
    decrypted = decrypt_license(encrypted)
    print(f"   Customer: {decrypted.customer_name}")
    print(f"   PO: {decrypted.po_number}")
    print(f"   Addons: {decrypted.licensed_addons}")

    # Verify
    print("\n4. Verification:")
    if license_data.to_json() == decrypted.to_json():
        print("   ✓ Roundtrip successful - data matches!")
    else:
        print("   ✗ Roundtrip failed - data mismatch!")

    print("\n" + "=" * 70)


if __name__ == '__main__':
    test_encryption()
