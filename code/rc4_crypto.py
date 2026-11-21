"""
Educational RC4 message encryption with password-based key derivation and HMAC.
WARNING: RC4 is cryptographically obsolete. This is for coursework/demo use only.
Do not use it to protect real or sensitive communications.
"""
import base64
import hashlib
import hmac
import os

from Crypto.Cipher import ARC4

MAGIC = b"RC4CHAT-v1"
PBKDF2_ITERATIONS = 150_000
SALT_BYTES = 16
ENC_KEY_BYTES = 32
MAC_KEY_BYTES = 32


def _derive_keys(password: str, salt: bytes):
    if not password:
        raise ValueError("Password cannot be empty.")
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt,
        PBKDF2_ITERATIONS, dklen=ENC_KEY_BYTES + MAC_KEY_BYTES
    )
    return material[:ENC_KEY_BYTES], material[ENC_KEY_BYTES:]


def encrypt_message(plaintext: str, password: str) -> dict:
    """Return a JSON-serializable envelope; plaintext is never sent to the relay."""
    salt = os.urandom(SALT_BYTES)
    enc_key, mac_key = _derive_keys(password, salt)
    ciphertext = ARC4.new(enc_key).encrypt(plaintext.encode("utf-8"))
    tag = hmac.new(mac_key, MAGIC + salt + ciphertext, hashlib.sha256).digest()
    return {
        "version": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_message(envelope: dict, password: str) -> str:
    """Verify the HMAC before decrypting; reject modified messages."""
    if envelope.get("version") != 1:
        raise ValueError("Unsupported message version.")
    try:
        salt = base64.b64decode(envelope["salt"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        supplied_tag = base64.b64decode(envelope["tag"], validate=True)
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Invalid encrypted message format.") from exc

    if len(salt) != SALT_BYTES:
        raise ValueError("Invalid salt length.")

    enc_key, mac_key = _derive_keys(password, salt)
    expected_tag = hmac.new(
        mac_key, MAGIC + salt + ciphertext, hashlib.sha256
    ).digest()

    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise ValueError("Message authentication failed (wrong password or tampering).")

    plaintext = ARC4.new(enc_key).decrypt(ciphertext)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted data is not valid UTF-8.") from exc
