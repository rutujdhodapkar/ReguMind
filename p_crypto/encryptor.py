"""
AES-256-GCM encryption module for Phantom Compliance.

All sensitive data at rest (circular text, MAP JSON, evidence)
MUST be encrypted using this module. Decryption occurs only into
RAM variables, and callers MUST clear those variables after use.

Cryptographic design:
  - AES-256-GCM (Authenticated Encryption with Associated Data)
  - Random 12-byte nonce per encryption (secrets.randbelow or os.urandom)
  - 16-byte GCM authentication tag
  - Storage format: nonce (12) + ciphertext + auth_tag (16)
  - Key: derived via SHA-256 of the master key for domain separation

Security invariants:
  1. Never log plaintext, keys, or nonces
  2. Never write plaintext to disk
  3. Use different nonce for every encryption call
  4. Verify auth tag on every decryption (gcm does this inherently)
"""

import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# Derive a domain-specific key from the master key to avoid key reuse
def _derive_key(master_key: bytes, domain: bytes) -> bytes:
    return hashlib.sha256(master_key + domain).digest()


def encrypt(plaintext: str, master_key: bytes, domain: bytes = b"compliance") -> tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext string with AES-256-GCM.

    Returns:
        (ciphertext, nonce, auth_tag)
    - ciphertext: the encrypted bytes (same length as plaintext)
    - nonce: 12-byte random value, MUST be stored for decryption
    - auth_tag: 16-byte GCM authentication tag
    """
    key = _derive_key(master_key, domain)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    return ciphertext, nonce, auth_tag


def decrypt(ciphertext: bytes, nonce: bytes, auth_tag: bytes, master_key: bytes, domain: bytes = b"compliance") -> str:
    """
    Decrypt AES-256-GCM ciphertext.

    Raises ValueError if authentication fails (data tampered or wrong key).
    Returns plaintext string. Caller MUST clear the returned variable after use.
    """
    key = _derive_key(master_key, domain)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
    return plaintext_bytes.decode("utf-8")


def encrypt_bytes(plaintext: bytes, master_key: bytes, domain: bytes = b"compliance") -> tuple[bytes, bytes, bytes]:
    """Encrypt raw bytes with AES-256-GCM."""
    key = _derive_key(master_key, domain)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, auth_tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, auth_tag


def decrypt_bytes(ciphertext: bytes, nonce: bytes, auth_tag: bytes, master_key: bytes, domain: bytes = b"compliance") -> bytes:
    """Decrypt AES-256-GCM ciphertext, returning raw bytes."""
    key = _derive_key(master_key, domain)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, auth_tag)
