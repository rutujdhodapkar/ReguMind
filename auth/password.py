"""
Password hashing module using bcrypt.
Never store or log plaintext passwords.
"""

import bcrypt


ROUNDS = 12


def hash_password(password: str) -> bytes:
    """Hash a password with bcrypt at 12 rounds. Returns the salted hash bytes."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=ROUNDS))


def verify_password(password: str, stored_hash: bytes) -> bool:
    """Verify a password against a bcrypt hash. Returns True if valid."""
    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)
