
import json
import sqlite3

import pytest

from app.evidence.processor import process_evidence
from app.evidence.registry import register_evidence
from app.evidence.verification import (
    verify_evidence,
    get_verification_history,
)
from database.connection import initialize_database


@pytest.fixture
def database(tmp_path):
    """Create an isolated temporary SQLite database."""
    db_path = tmp_path / "forensicai.db"
    initialize_database(db_path)
    return db_path


@pytest.fixture
def evidence_file(tmp_path):
    """Create synthetic JPEG evidence."""
    path = tmp_path / "evidence.jpg"
    path.write_bytes(
        bytes.fromhex("FF D8 FF") + b"synthetic evidence"
    )
    return path


@pytest.fixture
def registered_evidence(database, evidence_file):
    """Process and register synthetic evidence."""
    processed_record = process_evidence(evidence_file)

    register_evidence(
        database,
        processed_record,
        evidence_file,
    )

    return processed_record


def test_verify_evidence_baseline_match(
    database, registered_evidence
):
    result = verify_evidence(
        database,
        registered_evidence["evidence_id"],
        reference_source="REGISTERED_BASELINE",
    )

    assert result["verification_status"] == "MATCH"
    assert result["integrity_verified"] is True
    assert (
        result["expected_sha256"]
        == registered_evidence["calculated_sha256"]
    )
    assert (
        result["observed_sha256"]
        == registered_evidence["calculated_sha256"]
    )


def test_verify_evidence_external_hash_match(
    database, evidence_file, registered_evidence
):
    result = verify_evidence(
        database,
        registered_evidence["evidence_id"],
        reference_source="ACQUISITION_RECORD",
        expected_sha256=registered_evidence["calculated_sha256"],
        reference_description="Synthetic acquisition record TEST-001",
    )

    assert result["verification_status"] == "MATCH"
    assert result["reference_source"] == "ACQUISITION_RECORD"


def test_verify_evidence_mismatch(
    database, registered_evidence
):
    result = verify_evidence(
        database,
        registered_evidence["evidence_id"],
        reference_source="EXAMINER_SUPPLIED",
        expected_sha256="0" * 64,
        reference_description="Synthetic examiner reference TEST-002",
    )

    assert result["verification_status"] == "MISMATCH"
    assert result["integrity_verified"] is False
    assert result["expected_sha256"] != result["observed_sha256"]


def test_verification_history_is_saved(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]

    result = verify_evidence(
        database,
        evidence_id,
        reference_source="REGISTERED_BASELINE",
    )

    history = get_verification_history(
        database,
        evidence_id,
    )

    assert len(history) == 1
    assert history[0]["verification_id"] == result["verification_id"]
    assert history[0]["verification_status"] == "MATCH"


def test_multiple_verifications_are_preserved(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]

    first = verify_evidence(
        database,
        evidence_id,
        reference_source="REGISTERED_BASELINE",
    )

    second = verify_evidence(
        database,
        evidence_id,
        reference_source="EXAMINER_SUPPLIED",
        expected_sha256="0" * 64,
        reference_description="Synthetic second reference TEST-003",
    )

    history = get_verification_history(
        database,
        evidence_id,
    )

    assert len(history) == 2
    assert first["verification_id"] != second["verification_id"]


def test_reference_provenance_is_preserved(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]

    verify_evidence(
        database,
        evidence_id,
        reference_source="ACQUISITION_RECORD",
        expected_sha256=registered_evidence["calculated_sha256"],
        reference_description="Acquisition record TEST-004",
    )

    history = get_verification_history(
        database,
        evidence_id,
    )

    assert history[0]["reference_source"] == "ACQUISITION_RECORD"
    assert (
        history[0]["reference_description"]
        == "Acquisition record TEST-004"
    )


def test_audit_event_is_created(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]

    result = verify_evidence(
        database,
        evidence_id,
        reference_source="REGISTERED_BASELINE",
        actor="TEST-EXAMINER",
    )

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row

    try:
        row = connection.execute(
            """
            SELECT *
            FROM audit_logs
            WHERE audit_id = ?
            """,
            (result["audit_id"],),
        ).fetchone()

        assert row is not None
        assert row["evidence_id"] == evidence_id
        assert row["action"] == "EVIDENCE_VERIFICATION"
        assert row["actor"] == "TEST-EXAMINER"

        details = json.loads(row["details_json"])

        assert details["verification_id"] == result["verification_id"]
        assert details["verification_status"] == "MATCH"

    finally:
        connection.close()


def test_audit_failure_rolls_back_verification(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]

    connection = sqlite3.connect(database)

    try:
        connection.execute(
            """
            CREATE TRIGGER force_audit_failure
            BEFORE INSERT ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'Forced audit failure');
            END;
            """
        )
        connection.commit()

    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError):
        verify_evidence(
            database,
            evidence_id,
            reference_source="REGISTERED_BASELINE",
        )

    connection = sqlite3.connect(database)

    try:
        verification_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM verification_history
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()[0]

        audit_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()[0]

        assert verification_count == 0
        assert audit_count == 0

    finally:
        connection.close()


def test_invalid_sha256_rejected(
    database, registered_evidence
):
    with pytest.raises(ValueError, match="Invalid SHA-256"):
        verify_evidence(
            database,
            registered_evidence["evidence_id"],
            reference_source="EXAMINER_SUPPLIED",
            expected_sha256="invalid-hash",
            reference_description="Synthetic reference TEST-005",
        )


def test_missing_external_reference_hash_rejected(
    database, registered_evidence
):
    with pytest.raises(ValueError, match="required"):
        verify_evidence(
            database,
            registered_evidence["evidence_id"],
            reference_source="ACQUISITION_RECORD",
            reference_description="Synthetic reference TEST-006",
        )


def test_missing_reference_description_rejected(
    database, registered_evidence
):
    with pytest.raises(ValueError, match="description"):
        verify_evidence(
            database,
            registered_evidence["evidence_id"],
            reference_source="OTHER",
            expected_sha256="a" * 64,
        )


def test_unspecified_reference_source_rejected(
    database, registered_evidence
):
    with pytest.raises(ValueError, match="Unsupported"):
        verify_evidence(
            database,
            registered_evidence["evidence_id"],
            reference_source="UNSPECIFIED",
        )


def test_missing_evidence_id_rejected(database):
    with pytest.raises(ValueError, match="not found"):
        verify_evidence(
            database,
            "NONEXISTENT-EVIDENCE",
            reference_source="REGISTERED_BASELINE",
        )


def test_missing_evidence_file_rejected(
    database, registered_evidence, evidence_file
):
    evidence_file.unlink()

    with pytest.raises(FileNotFoundError):
        verify_evidence(
            database,
            registered_evidence["evidence_id"],
            reference_source="REGISTERED_BASELINE",
        )


def test_archived_evidence_rejected(
    database, registered_evidence
):
    connection = sqlite3.connect(database)

    try:
        connection.execute(
            """
            UPDATE evidence_records
            SET record_status = 'ARCHIVED'
            WHERE evidence_id = ?
            """,
            (registered_evidence["evidence_id"],),
        )
        connection.commit()

    finally:
        connection.close()

    with pytest.raises(ValueError, match="Archived"):
        verify_evidence(
            database,
            registered_evidence["evidence_id"],
            reference_source="REGISTERED_BASELINE",
        )


def test_baseline_hash_is_not_modified(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]
    original_hash = registered_evidence["calculated_sha256"]

    verify_evidence(
        database,
        evidence_id,
        reference_source="EXAMINER_SUPPLIED",
        expected_sha256="0" * 64,
        reference_description="Synthetic mismatch TEST-007",
    )

    connection = sqlite3.connect(database)

    try:
        stored_hash = connection.execute(
            """
            SELECT baseline_sha256
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()[0]

        assert stored_hash == original_hash

    finally:
        connection.close()


def test_original_evidence_file_is_not_modified(
    database, registered_evidence, evidence_file
):
    original_content = evidence_file.read_bytes()

    verify_evidence(
        database,
        registered_evidence["evidence_id"],
        reference_source="REGISTERED_BASELINE",
    )

    assert evidence_file.read_bytes() == original_content


def test_verification_timestamp_is_utc(
    database, registered_evidence
):
    result = verify_evidence(
        database,
        registered_evidence["evidence_id"],
        reference_source="REGISTERED_BASELINE",
    )

    from datetime import datetime, timezone

    timestamp = datetime.fromisoformat(
        result["verified_at_utc"]
    )

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_verification_history_pagination(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]

    for _ in range(3):
        verify_evidence(
            database,
            evidence_id,
            reference_source="REGISTERED_BASELINE",
        )

    first_page = get_verification_history(
        database,
        evidence_id,
        limit=2,
        offset=0,
    )

    second_page = get_verification_history(
        database,
        evidence_id,
        limit=2,
        offset=2,
    )

    assert len(first_page) == 2
    assert len(second_page) == 1


def test_invalid_pagination_rejected(
    database, registered_evidence
):
    evidence_id = registered_evidence["evidence_id"]

    with pytest.raises(ValueError):
        get_verification_history(
            database,
            evidence_id,
            limit=0,
        )

    with pytest.raises(ValueError):
        get_verification_history(
            database,
            evidence_id,
            offset=-1,
        )


def test_empty_evidence_file_can_be_verified(
    database, tmp_path
):
    empty_file = tmp_path / "empty.jpg"
    empty_file.write_bytes(b"")

    processed_record = process_evidence(empty_file)

    register_evidence(
        database,
        processed_record,
        empty_file,
    )

    result = verify_evidence(
        database,
        processed_record["evidence_id"],
        reference_source="REGISTERED_BASELINE",
    )

    assert result["verification_status"] == "MATCH"
    assert result["observed_sha256"] == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )
