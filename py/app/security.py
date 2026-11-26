from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import uuid

from cryptography.fernet import Fernet

from app.settings import Settings


PASSWORD_SCRYPT_N = 2**15
PASSWORD_SCRYPT_R = 8
PASSWORD_SCRYPT_P = 1


def normalize_document_number(value: str) -> str:
    normalized = re.sub(r"[\s-]", "", value).upper()
    if not re.fullmatch(r"[A-Z0-9]{2,32}", normalized):
        raise ValueError("ID or passport number must be 2–32 letters or digits.")
    return normalized


def document_lookup_hash(
    facility_id: uuid.UUID,
    document_type: str,
    document_number: str,
    settings: Settings,
) -> str:
    normalized = normalize_document_number(document_number)
    message = f"{facility_id}:{document_type}:{normalized}".encode()
    return hmac.new(settings.identifier_hmac_key.encode(), message, hashlib.sha256).hexdigest()


def admission_number_lookup_hash(
    facility_id: uuid.UUID,
    admission_number: str,
    settings: Settings,
) -> str:
    normalized = "".join(admission_number.upper().split())
    if not normalized or any(not (character.isalnum() or character in "/-") for character in normalized):
        raise ValueError("Admission or registration number may contain only letters, numbers, /, and -.")
    return keyed_hash(
        f"{facility_id}:admission:{normalized}",
        settings.identifier_hmac_key,
    )


def keyed_hash(value: str, key: str) -> str:
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def encrypt_text(value: str | None, settings: Settings) -> str | None:
    if value is None:
        return None
    cipher = Fernet(settings.data_encryption_key.encode())
    return cipher.encrypt(value.encode()).decode()


def decrypt_text(value: str | None, settings: Settings) -> str | None:
    if value is None:
        return None
    cipher = Fernet(settings.data_encryption_key.encode())
    return cipher.decrypt(value.encode()).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=PASSWORD_SCRYPT_N,
        r=PASSWORD_SCRYPT_R,
        p=PASSWORD_SCRYPT_P,
        dklen=64,
        maxmem=128 * 1024 * 1024,
    )
    return "$".join(
        (
            "scrypt",
            str(PASSWORD_SCRYPT_N),
            str(PASSWORD_SCRYPT_R),
            str(PASSWORD_SCRYPT_P),
            base64.urlsafe_b64encode(salt).decode(),
            base64.urlsafe_b64encode(digest).decode(),
        )
    )


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, digest_text = encoded_hash.split("$")
        if algorithm != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode())
        expected = base64.urlsafe_b64decode(digest_text.encode())
        actual = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=128 * 1024 * 1024,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def new_token() -> str:
    return secrets.token_urlsafe(32)
