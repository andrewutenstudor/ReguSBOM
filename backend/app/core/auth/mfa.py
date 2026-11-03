"""
ReguBOM — Enterprise Cyber Resilience & Regulatory SBOM Gateway
Multi-Factor Authentication (MFA) Engine.
Implements RFC 6238 TOTP (Microsoft Authenticator / Google Authenticator)
and cryptographically secure one-time emergency recovery codes.
"""
import base64
import io
import hashlib
import secrets
from typing import Tuple, List, Optional
import pyotp
import qrcode
from qrcode.image.pil import PilImage


ISSUER_NAME = "ReguBOM"


def generate_totp_secret() -> str:
    """Generates a standard 32-character base32 TOTP secret."""
    return pyotp.random_base32()


def generate_totp_uri(username: str, secret: str) -> str:
    """Generates the standard otpauth:// URI recognized by authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=ISSUER_NAME)


def generate_qr_code_base64(otpauth_uri: str) -> str:
    """
    Generates a PNG QR code for the otpauth URI and returns it as a
    base64 data URI ('data:image/png;base64,...') for zero-external-network frontend display.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(otpauth_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="white")

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64_str = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{b64_str}"


def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verifies a 6-digit TOTP code with standard ±1 time-step (30s) clock drift window.
    """
    if not secret or not code:
        return False
    clean_code = str(code).strip().replace(" ", "")
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    totp = pyotp.TOTP(secret)
    return bool(totp.verify(clean_code, valid_window=1))


def hash_recovery_code(code: str) -> str:
    """Hash an emergency recovery code using SHA-256."""
    return hashlib.sha256(code.strip().upper().encode("utf-8")).hexdigest()


def generate_recovery_codes(count: int = 8) -> Tuple[List[str], List[str]]:
    """
    Generates emergency one-time recovery codes (e.g. 'A1B2-C3D4').
    Returns (plain_codes, hashed_codes).
    """
    plain_codes = []
    hashed_codes = []
    for _ in range(count):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        code = f"{part1}-{part2}"
        plain_codes.append(code)
        hashed_codes.append(hash_recovery_code(code))

    return plain_codes, hashed_codes


def verify_and_consume_recovery_code(
    code: str,
    stored_hashed_codes: Optional[List[str]]
) -> Tuple[bool, List[str]]:
    """
    Verifies if a code matches an emergency recovery code.
    If valid, consumes (removes) that code from the list and returns (True, updated_list).
    """
    if not stored_hashed_codes or not code:
        return False, stored_hashed_codes or []

    candidate_hash = hash_recovery_code(code)
    if candidate_hash in stored_hashed_codes:
        updated_list = [h for h in stored_hashed_codes if h != candidate_hash]
        return True, updated_list

    return False, stored_hashed_codes
