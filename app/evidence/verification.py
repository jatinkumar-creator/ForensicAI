
import json
import re
import sqlite3

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from database.connection import get_connection
from app.integrity.hashing import calculate_sha256


ALLOWED_REFERENCE_SOURCES = {
    "REGISTERED_BASELINE",
    "ACQUISITION_RECORD",
    "EXAMINER_SUPPLIED",
    "OTHER",
}


def _validate_sha256(value: str) -> str:
    """
    Validate and normalize a SHA-256 hexadecimal digest.
    """

    if not isinstance(value, str):
        raise TypeError("SHA-256 hash must be a string.")

    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("Invalid SHA-256 hash.")

    return value.lower()


def verify_evidence(
    db_path: str | Path,
    evidence_id: str,
    reference_source: str,
    expected_sha256: str | None = None,
    reference_description: str | None = None,
    actor: str | None = None,
) -> dict:
    """
    Verify registered evidence against a documented reference hash.

    REGISTERED_BASELINE:
        Uses the baseline SHA-256 stored during registration.
        Do not supply expected_sha256 for this source.

    ACQUISITION_RECORD, EXAMINER_SUPPLIED, OTHER:
        Require an explicitly supplied expected_sha256 and
        a non-empty reference_description.

    Every completed verification creates:
        1. A verification_history record.
        2. A corresponding audit_logs record.

    Both records are committed in one SQLite transaction.

    A MISMATCH is a completed verification result, not an exception.
    """

    if not isinstance(evidence_id, str) or not evidence_id.strip():
        raise ValueError("A valid evidence ID is required.")

    if reference_source not in ALLOWED_REFERENCE_SOURCES:
        raise ValueError(
            f"Unsupported reference source: {reference_source}"
        )

    if reference_source == "REGISTERED_BASELINE":
        if expected_sha256 is not None:
            raise ValueError(
                "Do not supply expected_sha256 when using "
                "REGISTERED_BASELINE. The registered baseline "
                "will be retrieved automatically."
            )

        if reference_description is None:
            reference_description = (
                "Baseline SHA-256 recorded during evidence registration."
            )

    else:
        if expected_sha256 is None:
            raise ValueError(
                "An expected SHA-256 hash is required for this "
                "reference source."
            )

        if (
            not isinstance(reference_description, str)
            or not reference_description.strip()
        ):
            raise ValueError(
                "A reference description is required for "
                "external reference sources."
            )

        expected_sha256 = _validate_sha256(expected_sha256)

    if actor is not None:
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("Actor must be a non-empty string.")

    connection = get_connection(db_path)

    try:
        # Retrieve the registered evidence record.
        evidence = connection.execute(
            """
            SELECT
                evidence_id,
                source_path,
                baseline_sha256,
                record_status
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()

        if evidence is None:
            raise ValueError(
                f"Evidence ID not found: {evidence_id}"
            )

        if evidence["record_status"] != "ACTIVE":
            raise ValueError(
                "Archived evidence cannot be verified."
            )

        # Select the expected reference hash.
        if reference_source == "REGISTERED_BASELINE":
            expected_sha256 = _validate_sha256(
                evidence["baseline_sha256"]
            )

        evidence_path = Path(evidence["source_path"])

        if not evidence_path.exists():
            raise FileNotFoundError(
                f"Registered evidence file not found: {evidence_path}"
            )

        if not evidence_path.is_file():
            raise ValueError(
                "Registered evidence path is not a regular file."
            )

        # Check file metadata before hashing.
        initial_stat = evidence_path.stat()

        # Calculate the current SHA-256.
        observed_sha256 = calculate_sha256(evidence_path)

        # Check metadata again after hashing.
        final_stat = evidence_path.stat()

        if (
            initial_stat.st_size != final_stat.st_size
            or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        ):
            raise RuntimeError(
                "Evidence file changed during verification. "
                "No verification record was created."
            )

        # Determine verification result.
        verification_status = (
            "MATCH"
            if expected_sha256 == observed_sha256
            else "MISMATCH"
        )

        verification_id = str(uuid4())
        audit_id = str(uuid4())

        verified_at = datetime.now(timezone.utc).isoformat()

        # Prepare verification history record.
        verification_record = {
            "verification_id": verification_id,
            "evidence_id": evidence_id,
            "expected_sha256": expected_sha256,
            "reference_source": reference_source,
            "reference_description": reference_description,
            "observed_sha256": observed_sha256,
            "verification_status": verification_status,
            "verified_at_utc": verified_at,
        }

        # Prepare corresponding audit event.
        audit_details = {
            "verification_id": verification_id,
            "reference_source": reference_source,
            "reference_description": reference_description,
            "verification_status": verification_status,
            "expected_sha256": expected_sha256,
            "observed_sha256": observed_sha256,
        }

        details_json = json.dumps(
            audit_details,
            sort_keys=True,
        )

        # Insert verification history.
        connection.execute(
            """
            INSERT INTO verification_history (
                verification_id,
                evidence_id,
                expected_sha256,
                reference_source,
                reference_description,
                observed_sha256,
                verification_status,
                verified_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verification_id,
                evidence_id,
                expected_sha256,
                reference_source,
                reference_description,
                observed_sha256,
                verification_status,
                verified_at,
            ),
        )

        # Insert corresponding audit event.
        connection.execute(
            """
            INSERT INTO audit_logs (
                audit_id,
                evidence_id,
                action,
                event_timestamp_utc,
                actor,
                details_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                evidence_id,
                "EVIDENCE_VERIFICATION",
                verified_at,
                actor,
                details_json,
            ),
        )

        # Commit both records together.
        connection.commit()

        verification_record["audit_id"] = audit_id
        verification_record["integrity_verified"] = (
            verification_status == "MATCH"
        )

        return verification_record

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_verification_history(
    db_path: str | Path,
    evidence_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """
    Retrieve verification history for a registered evidence ID.

    Results are ordered by verification timestamp.
    Supports pagination.
    """

    if not isinstance(evidence_id, str) or not evidence_id.strip():
        raise ValueError("A valid evidence ID is required.")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("Limit must be a positive integer.")

    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("Offset must be a non-negative integer.")

    connection = get_connection(db_path)

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM verification_history
            WHERE evidence_id = ?
            ORDER BY verified_at_utc, verification_id
            LIMIT ? OFFSET ?
            """,
            (evidence_id, limit, offset),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
