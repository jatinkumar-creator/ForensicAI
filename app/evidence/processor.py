
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.ingestion.detector import (
    identify_file_format,
    check_extension_mismatch,
)
from app.integrity.hashing import calculate_sha256


def process_evidence(file_path: str | Path) -> dict:
    """
    Collect basic evidence metadata, identify its file format,
    and calculate a baseline SHA-256 hash.

    The original file is opened only for reading by the
    underlying detection and hashing functions.

    A calculated hash is a baseline, not independent proof
    of evidence integrity or acquisition authenticity.
    """

    path = Path(file_path)

    # Validate the input before processing.
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    # Collect initial file metadata.
    file_size = path.stat().st_size

    # Identify the file using its binary signature.
    detected_format = identify_file_format(path)

    # Check whether the filename extension matches the format.
    extension_info = check_extension_mismatch(path)

    # Calculate a baseline SHA-256 hash.
    calculated_hash = calculate_sha256(path)

    # Record the processing timestamp in UTC.
    processed_at = datetime.now(timezone.utc).isoformat()

    # Generate a unique evidence identifier.
    evidence_id = str(uuid4())

    return {
        "evidence_id": evidence_id,
        "filename": path.name,
        "file_size_bytes": file_size,
        "detected_format": detected_format,
        "file_extension": extension_info["extension"],
        "extension_mismatch": extension_info["extension_mismatch"],
        "hash_algorithm": "SHA-256",
        "calculated_sha256": calculated_hash,
        "hash_status": "BASELINE_CREATED",
        "processing_status": "COMPLETED",
        "processed_at_utc": processed_at,
    }
