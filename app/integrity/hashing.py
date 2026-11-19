
import hashlib
from pathlib import Path


def calculate_sha256(
    file_path: str | Path,
    chunk_size: int = 1024 * 1024
) -> str:
    """
    Calculate the SHA-256 hash of a file.

    Reads the file in chunks to avoid loading
    large forensic images entirely into memory.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    if chunk_size <= 0:
        raise ValueError("Chunk size must be greater than zero.")

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(chunk_size)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def verify_sha256(
    file_path: str | Path,
    original_hash: str,
    chunk_size: int = 1024 * 1024
) -> dict:
    """
    Compare the current file hash with a previously
    recorded SHA-256 hash.
    """

    if not isinstance(original_hash, str):
        raise TypeError("Original hash must be a string.")

    if len(original_hash) != 64:
        raise ValueError("Invalid SHA-256 hash length.")

    try:
        bytes.fromhex(original_hash)
    except ValueError as exc:
        raise ValueError("Original hash is not valid hexadecimal.") from exc

    current_hash = calculate_sha256(file_path, chunk_size)

    is_match = current_hash.lower() == original_hash.lower()

    return {
        "filename": Path(file_path).name,
        "algorithm": "SHA-256",
        "original_hash": original_hash.lower(),
        "current_hash": current_hash,
        "status": "MATCH" if is_match else "MISMATCH",
        "integrity_verified": is_match,
    }
