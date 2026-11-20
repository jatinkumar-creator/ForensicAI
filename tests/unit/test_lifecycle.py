
import hashlib

import pytest

from app.evidence import lifecycle
from app.evidence.lifecycle import register_and_verify_evidence
from app.evidence.registry import get_evidence
from database.connection import initialize_database


def create_test_evidence(tmp_path, filename="evidence.jpg"):
    """Create a small synthetic evidence file."""
    evidence_path = tmp_path / filename
    evidence_path.write_bytes(
        bytes.fromhex("FF D8 FF") + b"synthetic evidence data"
    )
    return evidence_path


def create_test_database(tmp_path):
    """Initialize an isolated SQLite database."""
    db_path = tmp_path / "forensicai_test.db"
    initialize_database(db_path)
    return db_path


def test_lifecycle_registers_and_verifies_baseline(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    result = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
    )

    assert result["lifecycle_status"] == "COMPLETED"
    assert result["evidence_record"]["filename"] == "evidence.jpg"
    assert result["verification"]["verification_status"] == "MATCH"
    assert result["verification"]["integrity_verified"] is True
    assert len(result["verification_history"]) == 1


def test_lifecycle_supports_optional_case_id(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    result = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
        case_id="CASE-001",
    )

    assert result["evidence_record"]["case_id"] == "CASE-001"


def test_lifecycle_supports_acquisition_metadata(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    metadata = {
        "acquisition_method": "Synthetic test acquisition",
        "acquisition_tool": "Test Tool",
        "acquisition_tool_version": "1.0",
    }

    result = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
        acquisition_metadata=metadata,
    )

    record = result["evidence_record"]

    assert record["acquisition_method"] == metadata["acquisition_method"]
    assert record["acquisition_tool"] == metadata["acquisition_tool"]
    assert record["acquisition_tool_version"] == "1.0"


def test_lifecycle_supports_external_reference_match(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    expected_hash = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()

    result = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
        reference_source="EXAMINER_SUPPLIED",
        expected_sha256=expected_hash,
        reference_description="Synthetic examiner reference",
        actor="Test Examiner",
    )

    assert result["verification"]["verification_status"] == "MATCH"
    assert result["verification"]["reference_source"] == "EXAMINER_SUPPLIED"
    assert result["verification"]["integrity_verified"] is True


def test_lifecycle_records_external_reference_mismatch(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    incorrect_hash = "0" * 64

    result = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
        reference_source="EXAMINER_SUPPLIED",
        expected_sha256=incorrect_hash,
        reference_description="Deliberately incorrect synthetic reference",
    )

    assert result["lifecycle_status"] == "COMPLETED"
    assert result["verification"]["verification_status"] == "MISMATCH"
    assert result["verification"]["integrity_verified"] is False
    assert len(result["verification_history"]) == 1


def test_lifecycle_creates_audit_record(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    result = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
        actor="Test Examiner",
    )

    assert result["verification"]["audit_id"]
    assert result["verification_history"][0]["verification_id"] == (
        result["verification"]["verification_id"]
    )


def test_invalid_reference_does_not_register_evidence(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    with pytest.raises(ValueError, match="Unsupported reference source"):
        register_and_verify_evidence(
            db_path=db_path,
            source_path=evidence_path,
            reference_source="INVALID_SOURCE",
        )


def test_invalid_external_hash_does_not_register_evidence(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    with pytest.raises(ValueError, match="Invalid SHA-256"):
        register_and_verify_evidence(
            db_path=db_path,
            source_path=evidence_path,
            reference_source="OTHER",
            expected_sha256="not-a-valid-hash",
            reference_description="Synthetic reference",
        )


def test_missing_external_description_does_not_register_evidence(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    with pytest.raises(ValueError, match="reference description"):
        register_and_verify_evidence(
            db_path=db_path,
            source_path=evidence_path,
            reference_source="OTHER",
            expected_sha256="a" * 64,
        )


def test_missing_evidence_file_is_rejected(tmp_path):
    db_path = create_test_database(tmp_path)
    missing_path = tmp_path / "missing.jpg"

    with pytest.raises(FileNotFoundError):
        register_and_verify_evidence(
            db_path=db_path,
            source_path=missing_path,
        )


def test_registration_remains_when_verification_fails(
    tmp_path,
    monkeypatch,
):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    def simulate_verification_failure(**kwargs):
        raise RuntimeError("Simulated verification failure")

    monkeypatch.setattr(
        lifecycle,
        "verify_evidence",
        simulate_verification_failure,
    )

    with pytest.raises(
        RuntimeError,
        match="Simulated verification failure",
    ):
        register_and_verify_evidence(
            db_path=db_path,
            source_path=evidence_path,
        )

    # Registration must remain committed even though
    # the subsequent verification operation failed.
    from app.evidence.registry import list_evidence

    records = list_evidence(db_path)

    assert len(records) == 1
    assert records[0]["filename"] == "evidence.jpg"

    saved_record = get_evidence(
        db_path,
        records[0]["evidence_id"],
    )

    assert saved_record is not None


def test_original_evidence_is_not_modified(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    original_content = evidence_path.read_bytes()
    original_hash = hashlib.sha256(original_content).hexdigest()

    register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
    )

    assert evidence_path.read_bytes() == original_content

    final_hash = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()

    assert final_hash == original_hash

def test_repeated_verification_preserves_same_evidence_id(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    initial = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
    )

    original_id = initial["evidence_record"]["evidence_id"]

    repeated = lifecycle.verify_registered_evidence(
        db_path=db_path,
        evidence_id=original_id,
    )

    assert repeated["lifecycle_status"] == "COMPLETED"
    assert repeated["evidence_id"] == original_id
    assert repeated["verification"]["verification_status"] == "MATCH"

    from app.evidence.registry import list_evidence

    records = list_evidence(db_path)

    assert len(records) == 1
    assert records[0]["evidence_id"] == original_id


def test_repeated_verification_preserves_history(tmp_path):
    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    initial = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
    )

    evidence_id = initial["evidence_record"]["evidence_id"]

    original_content = evidence_path.read_bytes()
    correct_hash = hashlib.sha256(original_content).hexdigest()

    repeated = lifecycle.verify_registered_evidence(
        db_path=db_path,
        evidence_id=evidence_id,
        reference_source="EXAMINER_SUPPLIED",
        expected_sha256=correct_hash,
        reference_description="Synthetic examiner reference",
    )

    history = repeated["verification_history"]

    assert repeated["evidence_id"] == evidence_id
    assert len(history) == 2

    assert history[0]["evidence_id"] == evidence_id
    assert history[1]["evidence_id"] == evidence_id

    assert {
        record["reference_source"] for record in history
    } == {
        "REGISTERED_BASELINE",
        "EXAMINER_SUPPLIED",
    }


def test_repeated_verification_creates_audit_records(tmp_path):
    from database.connection import get_connection

    evidence_path = create_test_evidence(tmp_path)
    db_path = create_test_database(tmp_path)

    initial = register_and_verify_evidence(
        db_path=db_path,
        source_path=evidence_path,
    )

    evidence_id = initial["evidence_record"]["evidence_id"]

    lifecycle.verify_registered_evidence(
        db_path=db_path,
        evidence_id=evidence_id,
    )

    connection = get_connection(db_path)

    try:
        rows = connection.execute(
            """
            SELECT action
            FROM audit_logs
            WHERE evidence_id = ?
            ORDER BY event_timestamp_utc, audit_id
            """,
            (evidence_id,),
        ).fetchall()

        assert len(rows) == 2
        assert all(
            row["action"] == "EVIDENCE_VERIFICATION"
            for row in rows
        )

    finally:
        connection.close()


def test_repeated_verification_rejects_invalid_evidence_id(tmp_path):
    db_path = create_test_database(tmp_path)

    with pytest.raises(ValueError, match="valid evidence ID"):
        lifecycle.verify_registered_evidence(
            db_path=db_path,
            evidence_id="",
        )
