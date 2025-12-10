# #!/usr/bin/env python3
# # scripts/generate_commit_proof.py
# import sys
# import base64
# from pathlib import Path
# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import padding, rsa
# from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

# # Paths (adjust if your files are in different places)
# STUDENT_PRIV_PEM = Path("student_private.pem")
# INSTRUCTOR_PUB_PEM = Path("instructor_public.pem")

# def load_private_key(path: Path):
#     data = path.read_bytes()
#     return serialization.load_pem_private_key(data, password=None)

# def load_public_key(path: Path):
#     data = path.read_bytes()
#     return serialization.load_pem_public_key(data)

# def sign_message(message: str, private_key) -> bytes:
#     """
#     Sign ASCII message string using RSA-PSS with SHA-256.
#     - message: ASCII string (40-char commit hash). IMPORTANT: sign the ASCII string bytes.
#     """
#     msg_bytes = message.encode("utf-8")   # ASCII/UTF-8 bytes
#     signature = private_key.sign(
#         msg_bytes,
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),
#             salt_length=padding.PSS.MAX_LENGTH  # Maximum salt length
#         ),
#         hashes.SHA256()
#     )
#     return signature

# def encrypt_with_public_key(data: bytes, public_key) -> bytes:
#     """
#     Encrypt bytes with RSA/OAEP using SHA-256.
#     """
#     ciphertext = public_key.encrypt(
#         data,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return ciphertext

# def main():
#     if len(sys.argv) >= 2:
#         commit_hash = sys.argv[1].strip()
#     else:
#         print("Usage: generate_commit_proof.py <commit_hash>", file=sys.stderr)
#         return 2

#     if len(commit_hash) != 40:
#         print("Error: commit hash must be 40 hex chars", file=sys.stderr)
#         return 3

#     priv = load_private_key(STUDENT_PRIV_PEM)
#     pub = load_public_key(INSTRUCTOR_PUB_PEM)

#     sig = sign_message(commit_hash, priv)              # bytes
#     cipher = encrypt_with_public_key(sig, pub)        # bytes
#     b64 = base64.b64encode(cipher).decode("utf-8")    # string

#     # Print outputs exactly as required:
#     print("COMMIT_HASH:", commit_hash)
#     print("ENCRYPTED_COMMIT_SIGNATURE_BASE64:")   # evaluator expects a single-line base64 string
#     print(b64)                                   # must be single-line
#     return 0

# if __name__ == "__main__":
#     raise SystemExit(main())
# generate_commit_proof.py
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import subprocess
from pathlib import Path

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

def get_latest_commit_hash() -> str:
    result = subprocess.run(
        ["git", "log", "-1", "--format=%H"],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()

def sign_message(message: str, private_key) -> bytes:
    return private_key.sign(
        message.encode("utf-8"),  # ASCII string of commit hash
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent

    commit_hash = get_latest_commit_hash()
    print("Commit Hash:", commit_hash)

    student_priv = load_private_key(str(repo_root / "student_private.pem"))
    instructor_pub = load_public_key(str(repo_root / "instructor_public.pem"))

    signature = sign_message(commit_hash, student_priv)
    encrypted_sig = encrypt_with_public_key(signature, instructor_pub)

    b64 = base64.b64encode(encrypted_sig).decode("ascii")
    print("\n=== Encrypted Signature (single line) ===")
    print(b64)