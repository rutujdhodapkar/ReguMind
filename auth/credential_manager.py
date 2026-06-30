"""
Windows Credential Manager integration using keyring.
Stores admin password and JWT secret securely in Windows Credential Manager
instead of config.json on disk.
"""

import keyring
import logging

logger = logging.getLogger("phantom_compliance.credential_manager")

SERVICE_NAME = "PhantomCompliance"


def store_password(username: str, password: str):
    keyring.set_password(SERVICE_NAME, username, password)
    logger.info(f"Stored password for {username} in Windows Credential Manager")


def get_password(username: str) -> str | None:
    return keyring.get_password(SERVICE_NAME, username)


def delete_password(username: str):
    try:
        keyring.delete_password(SERVICE_NAME, username)
    except keyring.errors.PasswordDeleteError:
        pass


def store_admin_password(password: str):
    store_password("admin", password)


def get_admin_password() -> str | None:
    return get_password("admin")


def store_jwt_secret(secret: str):
    store_password("jwt_secret", secret)


def get_jwt_secret() -> str | None:
    return get_password("jwt_secret")
