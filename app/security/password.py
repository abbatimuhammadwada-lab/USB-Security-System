"""
Password hashing and strength validation.

Uses Argon2id (via argon2-cffi) as required by Section 3/25. Never stores
or logs plaintext passwords anywhere - not in the database, not in
application logs, not in exceptions.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

from app.core.exceptions import AuthenticationError

# Argon2id is the default variant for argon2-cffi's PasswordHasher.
# Parameters chosen as a reasonable desktop-app default (not tuned for a
# high-throughput server); documented here so a future security review
# can adjust deliberately rather than guessing why these numbers exist.
_hasher = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password. Raises AuthenticationError on empty input."""
    if not plain_password:
        raise AuthenticationError("Password must not be empty.")
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Verify a plaintext password against a stored Argon2id hash.
    Returns False on mismatch or malformed hash - never raises for
    normal "wrong password" cases, so callers can treat this as a
    simple boolean check.
    """
    if not plain_password or not password_hash:
        return False
    try:
        _hasher.verify(password_hash, plain_password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True if the stored hash was created with weaker/older parameters
    than the current policy and should be re-hashed on next successful login."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHash:
        return True


def validate_password_strength(plain_password: str) -> list[str]:
    """
    Return a list of human-readable policy violations (empty list = OK).
    Kept intentionally simple for a desktop/academic deployment; documented
    so it can be tightened without touching call sites.
    """
    problems: list[str] = []
    if len(plain_password) < 10:
        problems.append("Password must be at least 10 characters long.")
    if not any(c.isalpha() for c in plain_password):
        problems.append("Password must contain at least one letter.")
    if not any(c.isdigit() for c in plain_password):
        problems.append("Password must contain at least one digit.")
    if plain_password.lower() in {"password", "admin", "changeme", "12345678"}:
        problems.append("Password is too common/predictable.")
    return problems
