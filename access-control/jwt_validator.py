#!/usr/bin/env python3
"""
COLOSSUS JWT VALIDATOR
HMAC-SHA256 JWT creation and validation for inter-service auth.
No external dependencies — pure stdlib.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Dict, Optional, Tuple


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def create_token(
    payload: Dict,
    secret: str,
    ttl_seconds: int = 3600,
    algorithm: str = "HS256",
) -> str:
    """Create a signed JWT with expiry."""
    header = {"alg": algorithm, "typ": "JWT"}
    now = int(time.time())
    payload = {
        **payload,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    header_enc  = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_enc = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_enc}.{payload_enc}"
    sig = hmac.new(
        secret.encode(),
        signing_input.encode(),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_b64url_encode(sig)}"


def validate_token(
    token: str,
    secret: str,
) -> Tuple[bool, Optional[Dict], Optional[str]]:
    """
    Validate a JWT.
    Returns (valid, payload, error_message).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return False, None, "Malformed token: expected 3 parts"

    header_enc, payload_enc, sig_enc = parts
    signing_input = f"{header_enc}.{payload_enc}"

    # Signature check
    expected_sig = hmac.new(
        secret.encode(),
        signing_input.encode(),
        hashlib.sha256,
    ).digest()
    try:
        actual_sig = _b64url_decode(sig_enc)
    except Exception:
        return False, None, "Invalid signature encoding"

    if not hmac.compare_digest(expected_sig, actual_sig):
        return False, None, "Signature verification failed"

    # Decode payload
    try:
        payload = json.loads(_b64url_decode(payload_enc))
    except Exception:
        return False, None, "Failed to decode payload"

    # Expiry check
    exp = payload.get("exp")
    if exp and time.time() > exp:
        return False, None, "Token expired"

    return True, payload, None


if __name__ == "__main__":
    SECRET = "colossus-test-secret-do-not-use-in-prod"

    # Issue a token
    token = create_token(
        payload={"sub": "operator-01", "role": "operator"},
        secret=SECRET,
        ttl_seconds=60,
    )
    print(f"Token: {token[:60]}...")

    # Validate
    valid, payload, err = validate_token(token, SECRET)
    print(f"Valid: {valid} | Payload: {payload} | Error: {err}")

    # Tampered token
    tampered = token[:-4] + "XXXX"
    valid2, _, err2 = validate_token(tampered, SECRET)
    print(f"Tampered valid: {valid2} | Error: {err2}")
