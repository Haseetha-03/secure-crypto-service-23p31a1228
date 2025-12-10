# totp_utils.py
import base64
import pyotp


def _hex_to_base32(hex_seed: str) -> str:
    hex_seed = hex_seed.strip()
    seed_bytes = bytes.fromhex(hex_seed)
    return base64.b32encode(seed_bytes).decode("utf-8")


def generate_totp_code(hex_seed: str) -> str:
    base32_seed = _hex_to_base32(hex_seed)
    # pyotp.TOTP default: SHA-1, 30s interval, 6 digits -> matches spec
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    base32_seed = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)
