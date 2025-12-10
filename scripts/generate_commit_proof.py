#!/usr/bin/env python3
# scripts/generate_commit_proof.py

import base64
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


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
    # repo_root is the folder that contains student_private.pem, instructor_public.pem
    # __file__ = scripts/generate_commit_proof.py
    # parent = scripts/
    # parent.parent = repo root (secure-crypto-service-23p31a1228)
    repo_root = Path(__file__).resolve().parent.parent

    commit_hash = get_latest_commit_hash()
    print("Commit Hash:", commit_hash)

    student_priv = load_private_key(str(repo_root / "student_private.pem"))
    instructor_pub = load_public_key(str(repo_root / "instructor_public.pem"))

    signature = sign_message(commit_hash, student_priv)
    encrypted_sig = encrypt_with_public_key(signature, instructor_pub)

    b64 = base64.b64encode(encrypted_sig).decode("ascii")
    print("\n=== Encrypted Signature (single line) ===")
    print(b64)

