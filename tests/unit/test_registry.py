
import sqlite3

import pytest

from app.evidence.processor import process_evidence
from app.evidence.registry import (
    register_evidence,
    get_evidence,
    list_evidence,
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
def processed_record(evidence_file):
    """Generate a processed evidence record."""
    return process_evidence(evidence_file)


def test_register_evidence_success(
    database, evidence_file, processed_record
):
    result = register_evidence(
        database,
        processed_record,
        evidence_file,
    )

    assert result["evidence_id"] == processed_record["evidence_id"]
    assert result["filename"] == "evidence.jpg"
    assert result["record_status"] == "ACTIVE"
    assert result["hash_algorithm"] == "SHA-256"
    assert (
        result["baseline_sha256"]
        == processed_record["calculated_sha256"]
    )


def test_get_evidence_by_id(
    database, evidence_file, processed_record
):
    register_evidence(
        database,
        processed_record,
        evidence_file,
    )

    result = get_evidence(
        database,
        processed_record["evidence_id"],
    )

    assert result is not None
    assert result["evidence_id"] == processed_record["evidence_id"]


def test_get_nonexistent_evidence(database):
    result = get_evidence(database, "nonexistent-id")

    assert result is None


def test_list_evidence(database, tmp_path):
    first_file = tmp_path / "first.jpg"
    first_file.write_bytes(
        bytes.fromhex("FF D8 FF") + b"first"
    )

    first_record = process_evidence(first_file)

    register_evidence(
        database,
        first_record,
        first_file,
    )

    second_file = tmp_path / "second.jpg"
    second_file.write_bytes(
        bytes.fromhex("FF D8 FF") + b"second"
    )

    second_record = process_evidence(second_file)

    register_evidence(
        database,
        second_record,
        second_file,
    )

    results = list_evidence(database)

    assert len(results) == 2


def test_filter_evidence_by_case(
    database, evidence_file, processed_record
):
    register_evidence(
        database,
        processed_record,
        evidence_file,
        case_id="CASE-001",
    )

    results = list_evidence(
        database,
        case_id="CASE-001",
    )

    assert len(results) == 1
    assert results[0]["case_id"] == "CASE-001"


def test_duplicate_evidence_id_rejected(
    database, evidence_file, processed_record
):
    register_evidence(
        database,
        processed_record,
        evidence_file,
    )

    with pytest.raises(sqlite3.IntegrityError):
        register_evidence(
            database,
            processed_record,
            evidence_file,
        )


def test_modified_evidence_rejected(
    database, evidence_file, processed_record
):
    evidence_file.write_bytes(
        bytes.fromhex("FF D8 FF") + b"modified evidence"
    )

    with pytest.raises(ValueError, match="changed"):
        register_evidence(
            database,
            processed_record,
            evidence_file,
        )


def test_filename_mismatch_rejected(
    database, evidence_file, processed_record, tmp_path
):
    renamed_file = tmp_path / "renamed.jpg"
    renamed_file.write_bytes(evidence_file.read_bytes())

    with pytest.raises(ValueError, match="filename"):
        register_evidence(
            database,
            processed_record,
            renamed_file,
        )


def test_file_size_mismatch_rejected(
    database, evidence_file, processed_record
):
    modified_record = processed_record.copy()
    modified_record["file_size_bytes"] += 1

    with pytest.raises(ValueError, match="file size"):
        register_evidence(
            database,
            modified_record,
            evidence_file,
        )


def test_optional_acquisition_metadata(
    database, evidence_file, processed_record
):
    metadata = {
        "acquisition_method": "Synthetic test acquisition",
        "acquisition_tool": "ForensicAI Test",
        "examiner_reference": "TEST-EXAMINER-001",
    }

    result = register_evidence(
        database,
        processed_record,
        evidence_file,
        acquisition_metadata=metadata,
    )

    assert (
        result["acquisition_method"]
        == "Synthetic test acquisition"
    )
    assert result["acquisition_tool"] == "ForensicAI Test"
    assert result["examiner_reference"] == "TEST-EXAMINER-001"


def test_baseline_hash_preserved(
    database, evidence_file, processed_record
):
    original_hash = processed_record["calculated_sha256"]

    register_evidence(
        database,
        processed_record,
        evidence_file,
    )

    result = get_evidence(
        database,
        processed_record["evidence_id"],
    )

    assert result["baseline_sha256"] == original_hash


def test_invalid_pagination_rejected(database):
    with pytest.raises(ValueError):
        list_evidence(database, limit=0)

    with pytest.raises(ValueError):
        list_evidence(database, offset=-1)


def test_missing_evidence_file_rejected(
    database, processed_record, tmp_path
):
    missing_file = tmp_path / "missing.jpg"

    with pytest.raises(FileNotFoundError):
        register_evidence(
            database,
            processed_record,
            missing_file,
        )
