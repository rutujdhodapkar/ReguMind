"""
JWT session management. Tokens are signed with a locally generated
secret key (stored in AppData/Roaming/.jwt_secret, generated once on install).
Tokens expire after 8 hours.
"""

import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional


SESSION_EXPIRY_HOURS = 8


def create_token(username: str, role: str, user_id: int, secret: str) -> str:
    """Create a JWT token with 8-hour expiry."""
    payload = {
        "username": username,
        "role": role,
        "user_id": user_id,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=SESSION_EXPIRY_HOURS),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def verify_token(token: str, secret: str) -> Optional[dict]:
    """
    Verify and decode a JWT token.
    Returns the payload dict if valid, None otherwise.
    """
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
