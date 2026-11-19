
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from database.connection import get_connection
from app.integrity.hashing import calculate_sha256


REQUIRED_FIELDS = {
    "evidence_id",
    "filename",
    "file_size_bytes",
    "detected_format",
    "file_extension",
    "extension_mismatch",
    "hash_algorithm",
    "calculated_sha256",
}


OPTIONAL_ACQUISITION_FIELDS = {
    "acquisition_time_utc",
    "acquisition_method",
    "acquisition_tool",
    "acquisition_tool_version",
    "source_description",
    "examiner_reference",
}


def register_evidence(
    db_path: str | Path,
    processed_record: dict,
    source_path: str | Path,
    case_id: str | None = None,
    acquisition_metadata: dict | None = None,
) -> dict:
    """
    Register processed evidence in the SQLite evidence registry.

    Before registration, the source file is revalidated against
    the previously calculated SHA-256 hash, filename and file size.

    The calculated hash is stored as the baseline hash.
    Registration does not independently establish acquisition
    authenticity or prove the original evidence was authentic.
    """

    # Validate the processed record.
    if not isinstance(processed_record, dict):
        raise TypeError("Processed record must be a dictionary.")

    missing_fields = REQUIRED_FIELDS - processed_record.keys()

    if missing_fields:
        raise ValueError(
            f"Processed record is missing fields: "
            f"{sorted(missing_fields)}"
        )

    # Validate source path.
    path = Path(source_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Evidence file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Not a regular evidence file: {path}"
        )

    # Validate acquisition metadata.
    if acquisition_metadata is None:
        acquisition_metadata = {}

    if not isinstance(acquisition_metadata, dict):
        raise TypeError(
            "Acquisition metadata must be a dictionary."
        )

    unexpected_fields = (
        acquisition_metadata.keys() - OPTIONAL_ACQUISITION_FIELDS
    )

    if unexpected_fields:
        raise ValueError(
            f"Unsupported acquisition fields: "
            f"{sorted(unexpected_fields)}"
        )

    # Validate hash algorithm.
    if processed_record["hash_algorithm"] != "SHA-256":
        raise ValueError(
            "Only SHA-256 is supported by this registry."
        )

    expected_hash = processed_record["calculated_sha256"]

    if not isinstance(expected_hash, str):
        raise TypeError(
            "Processed SHA-256 hash must be a string."
        )

    # Capture file metadata before revalidation.
    initial_stat = path.stat()

    # Recalculate SHA-256 to ensure the source file has not changed.
    current_hash = calculate_sha256(path)

    if current_hash.lower() != expected_hash.lower():
        raise ValueError(
            "Evidence file has changed since initial processing. "
            "Registration rejected."
        )

    # Confirm filename consistency.
    if path.name != processed_record["filename"]:
        raise ValueError(
            "Source filename does not match the processed "
            "evidence record."
        )

    # Confirm file size consistency.
    if initial_stat.st_size != processed_record["file_size_bytes"]:
        raise ValueError(
            "Source file size does not match the processed "
            "evidence record."
        )

    # Check that the file was not modified during revalidation.
    final_stat = path.stat()

    if (
        initial_stat.st_size != final_stat.st_size
        or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
    ):
        raise ValueError(
            "Evidence file metadata changed during registration. "
            "Registration rejected."
        )

    # Prepare the evidence record.
    registered_at = datetime.now(timezone.utc).isoformat()

    record = {
        "evidence_id": processed_record["evidence_id"],
        "case_id": case_id,
        "filename": processed_record["filename"],
        "source_path": str(path.resolve()),
        "file_size_bytes": processed_record["file_size_bytes"],
        "detected_format": processed_record["detected_format"],
        "file_extension": processed_record["file_extension"],
        "extension_mismatch": int(
            processed_record["extension_mismatch"]
        ),
        "hash_algorithm": processed_record["hash_algorithm"],
        "baseline_sha256": expected_hash.lower(),
        "registered_at_utc": registered_at,
        "record_status": "ACTIVE",
    }

    # Add optional acquisition metadata.
    for field in OPTIONAL_ACQUISITION_FIELDS:
        record[field] = acquisition_metadata.get(field)

    # Insert the record into SQLite.
    connection = get_connection(db_path)

    try:
        columns = ", ".join(record.keys())
        placeholders = ", ".join("?" for _ in record)

        connection.execute(
            f"""
            INSERT INTO evidence_records ({columns})
            VALUES ({placeholders})
            """,
            tuple(record.values()),
        )

        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()

    return record


def get_evidence(
    db_path: str | Path,
    evidence_id: str,
) -> dict | None:
    """
    Retrieve one evidence record using its evidence ID.

    Returns None if the evidence ID does not exist.
    """

    connection = get_connection(db_path)

    try:
        row = connection.execute(
            """
            SELECT *
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()

        return dict(row) if row is not None else None

    finally:
        connection.close()


def list_evidence(
    db_path: str | Path,
    case_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """
    List registered evidence records.

    Supports optional case filtering and pagination.
    """

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError(
            "Limit must be a positive integer."
        )

    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError(
            "Offset must be a non-negative integer."
        )

    connection = get_connection(db_path)

    try:
        if case_id is None:
            rows = connection.execute(
                """
                SELECT *
                FROM evidence_records
                ORDER BY registered_at_utc, evidence_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        else:
            rows = connection.execute(
                """
                SELECT *
                FROM evidence_records
                WHERE case_id = ?
                ORDER BY registered_at_utc, evidence_id
                LIMIT ? OFFSET ?
                """,
                (case_id, limit, offset),
            ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
