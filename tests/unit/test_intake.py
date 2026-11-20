
import pytest

from app.cases.manager import create_case, close_case
from app.evidence.intake import intake_evidence
from app.evidence.registry import list_evidence
from database.connection import initialize_database


@pytest.fixture
def database(tmp_path):
    """Create an isolated test database."""
    db_path = tmp_path / "forensicai_test.db"
    initialize_database(db_path)
    return db_path


@pytest.fixture
def open_case(database):
    """Create an open case for testing."""
    return create_case(
        database,
        title="Synthetic Evidence Intake Test",
        actor="TEST",
    )


@pytest.fixture
def evidence_file(tmp_path):
    """Create a synthetic JPEG-like test file."""
    path = tmp_path / "evidence.jpg"
    path.write_bytes(
        bytes.fromhex("FF D8 FF") + b"synthetic evidence"
    )
    return path


def test_intake_evidence_success(
    database, open_case, evidence_file
):
    result = intake_evidence(
        database,
        evidence_file,
        open_case["case_id"],
    )

    assert result["case_id"] == open_case["case_id"]
    assert result["filename"] == "evidence.jpg"
    assert result["record_status"] == "ACTIVE"
    assert result["hash_algorithm"] == "SHA-256"


def test_intake_rejects_unknown_case(
    database, evidence_file
):
    with pytest.raises(ValueError, match="Case not found"):
        intake_evidence(
            database,
            evidence_file,
            "UNKNOWN-CASE",
        )

    assert list_evidence(database) == []


def test_intake_rejects_closed_case(
    database, open_case, evidence_file
):
    close_case(
        database,
        open_case["case_id"],
        actor="TEST",
    )

    with pytest.raises(
        ValueError,
        match="case with status: CLOSED",
    ):
        intake_evidence(
            database,
            evidence_file,
            open_case["case_id"],
        )

    assert list_evidence(database) == []


def test_intake_rejects_empty_case_id(
    database, evidence_file
):
    with pytest.raises(ValueError, match="cannot be empty"):
        intake_evidence(
            database,
            evidence_file,
            "   ",
        )


def test_intake_rejects_non_string_case_id(
    database, evidence_file
):
    with pytest.raises(TypeError, match="must be a string"):
        intake_evidence(
            database,
            evidence_file,
            None,
        )


def test_intake_rejects_missing_evidence_file(
    database, open_case, tmp_path
):
    missing_file = tmp_path / "missing.jpg"

    with pytest.raises(FileNotFoundError):
        intake_evidence(
            database,
            missing_file,
            open_case["case_id"],
        )

    assert list_evidence(database) == []
