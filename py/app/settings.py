from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.fernet import Fernet


def _read_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str
    data_encryption_key: str
    identifier_hmac_key: str
    session_hmac_key: str
    app_env: str = "development"
    cookie_secure: bool = False
    reader_mode: str = "mock"
    trusted_hosts: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> Settings:
        required = (
            "DATA_ENCRYPTION_KEY",
            "IDENTIFIER_HMAC_KEY",
            "SESSION_HMAC_KEY",
        )
        missing = [key for key in required if not os.environ.get(key)]
        if missing:
            raise RuntimeError(
                "Missing required configuration: "
                + ", ".join(missing)
                + ". Copy .env.example to .env and generate unique keys."
            )

        app_env = os.environ.get("APP_ENV", "development").strip().lower()
        reader_mode = os.environ.get("READER_MODE", "mock").strip().lower()
        trusted_hosts = tuple(
            host.strip().lower()
            for host in os.environ.get("TRUSTED_HOSTS", "").split(",")
            if host.strip()
        )
        cookie_secure = _read_bool("COOKIE_SECURE", app_env == "production")
        if app_env not in {"development", "test", "production"}:
            raise RuntimeError("APP_ENV must be development, test, or production.")
        if reader_mode not in {"mock", "device"}:
            raise RuntimeError("READER_MODE must be mock or device.")
        if app_env == "production" and (not cookie_secure or reader_mode != "device"):
            raise RuntimeError(
                "Production requires COOKIE_SECURE=true and READER_MODE=device."
            )
        if app_env == "production" and (
            not trusted_hosts or "*" in trusted_hosts
        ):
            raise RuntimeError(
                "Production requires explicit TRUSTED_HOSTS; a wildcard host is not allowed."
            )

        database_url = os.environ.get("DATABASE_URL")
        if app_env == "production" and (
            database_url is None
            or not database_url.startswith("postgresql+psycopg://")
        ):
            raise RuntimeError("Production requires a PostgreSQL DATABASE_URL.")
        settings = cls(
            database_url=database_url or "sqlite:///./gatepass_backend.sqlite3",
            data_encryption_key=os.environ["DATA_ENCRYPTION_KEY"],
            identifier_hmac_key=os.environ["IDENTIFIER_HMAC_KEY"],
            session_hmac_key=os.environ["SESSION_HMAC_KEY"],
            app_env=app_env,
            cookie_secure=cookie_secure,
            reader_mode=reader_mode,
            trusted_hosts=trusted_hosts,
        )
        if len(settings.identifier_hmac_key.encode()) < 32:
            raise RuntimeError("IDENTIFIER_HMAC_KEY must contain at least 32 bytes.")
        if len(settings.session_hmac_key.encode()) < 32:
            raise RuntimeError("SESSION_HMAC_KEY must contain at least 32 bytes.")
        try:
            Fernet(settings.data_encryption_key.encode())
        except (TypeError, ValueError) as exc:
            raise RuntimeError("DATA_ENCRYPTION_KEY must be a Fernet key.") from exc
        return settings
