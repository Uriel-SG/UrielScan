import os
import json
import time
import base64
import struct
import hmac
import hashlib
import secrets
import urllib.parse
from typing import Dict, Any, Optional, Tuple

import qrcode
import qrcode.image.svg

SESSION_SECRET = os.getenv("URIELSCAN_SESSION_SECRET", "urielscan-mssp-purple-secret-key-super-secure-production-ready")


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Generates PBKDF2-HMAC-SHA256 password hash and salt."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()
    return hashed, salt


def verify_password(password: str, salt: str, password_hash: str) -> bool:
    """Verifies a plain password against the stored PBKDF2 hash."""
    hashed, _ = hash_password(password, salt)
    return hmac.compare_digest(hashed, password_hash)


def generate_totp_secret() -> str:
    """Generates a 160-bit (20 bytes) Base32 secret without '=' padding for RFC 6238 TOTP."""
    raw_bytes = secrets.token_bytes(20)
    return base64.b32encode(raw_bytes).decode("ascii").rstrip("=")


def get_otpauth_uri(username: str, secret: str, issuer: str = "UrielScan") -> str:
    """Constructs the standard otpauth:// URI recognized by all Authenticator apps."""
    label = urllib.parse.quote(f"{issuer}:{username}")
    iss = urllib.parse.quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={iss}&algorithm=SHA1&digits=6&period=30"


def generate_totp_code(secret: str, time_step: Optional[int] = None, interval: int = 30, digits: int = 6) -> str:
    """Calculates standard RFC 6238 TOTP code for a given time step."""
    secret_clean = secret.strip().replace(" ", "").upper()
    missing_padding = len(secret_clean) % 8
    if missing_padding != 0:
        secret_clean += "=" * (8 - missing_padding)
    key = base64.b32decode(secret_clean, casefold=True)

    if time_step is None:
        time_step = int(time.time()) // interval

    msg = struct.pack(">Q", time_step)
    h = hmac.new(key, msg, hashlib.sha1).digest()

    offset = h[-1] & 0x0F
    code_int = (
        ((h[offset] & 0x7F) << 24)
        | ((h[offset + 1] & 0xFF) << 16)
        | ((h[offset + 2] & 0xFF) << 8)
        | (h[offset + 3] & 0xFF)
    ) % (10 ** digits)
    return str(code_int).zfill(digits)


def verify_totp_code(secret: str, code: str, window: int = 1, interval: int = 30) -> bool:
    """Verifies a 6-digit TOTP code across current time step +/- window steps."""
    if not secret or not code:
        return False
    code_str = str(code).strip()
    if not code_str.isdigit() or len(code_str) != 6:
        return False

    current_step = int(time.time()) // interval
    for step in range(current_step - window, current_step + window + 1):
        if hmac.compare_digest(generate_totp_code(secret, time_step=step, interval=interval), code_str):
            return True
    return False


def generate_qr_svg_data_uri(otpauth_uri: str) -> str:
    """Generates an inline SVG Data URI for the TOTP otpauth URI without external OS dependencies."""
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(otpauth_uri, image_factory=factory)
    svg_bytes = img.to_string()
    b64 = base64.b64encode(svg_bytes).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def create_session_token(username: str, role: str, expires_in_seconds: int = 86400, is_temp: bool = False) -> str:
    """Creates a HMAC-SHA256 signed session token."""
    payload = {
        "sub": username,
        "role": role,
        "temp": is_temp,
        "exp": int(time.time()) + expires_in_seconds,
        "iat": int(time.time())
    }
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    p_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), p_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{p_b64}.{sig}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Validates and decodes a signed session token. Returns payload dict or None."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        p_b64, sig = parts
        expected_sig = hmac.new(SESSION_SECRET.encode("utf-8"), p_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig):
            return None

        padded = p_b64 + "=" * ((4 - len(p_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


# Aliases for developer convenience
verify_totp = verify_totp_code
generate_qr_svg = generate_qr_svg_data_uri
create_token = create_session_token
decode_token = verify_session_token

