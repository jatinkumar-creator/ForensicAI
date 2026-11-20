
import json
import sqlite3
import hashlib

import pytest

from datetime import datetime

from app.evidence.handling import (
    record_handling_event,
    get_handling_history,
)

from app.evidence.processor import process_evidence
from app.evidence.registry import register_evidence
from database.connection import initialize_database


def create_test_evidence(tmp_path):
    """Create synthetic evidence for handling tests."""

    evidence_path = tmp_path / "synthetic.jpg"

    evidence_path.write_bytes(
        bytes.fromhex("FF D8 FF") + b"synthetic forensic evidence"
    )

    return evidence_path


def create_test_database(tmp_path):
    """Initialize an isolated test database."""

    db_path = tmp_path / "handling_test.db"
    initialize_database(db_path)

    return db_path


def register_test_evidence(db_path, evidence_path):
    """Process and register synthetic evidence."""

    processed_record = process_evidence(evidence_path)

    return register_evidence(
        db_path=db_path,
        processed_record=processed_record,
        source_path=evidence_path,
    )


def create_registered_test_case(tmp_path):
    """Create a database and one registered evidence record."""

    db_path = create_test_database(tmp_path)
    evidence_path = create_test_evidence(tmp_path)

    registered_record = register_test_evidence(
        db_path,
        evidence_path,
    )

    return db_path, evidence_path, registered_record


def test_record_handling_event_successfully(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    result = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="RECEIVED",
        actor="Test Examiner",
    )

    assert result["evidence_id"] == evidence["evidence_id"]
    assert result["event_type"] == "RECEIVED"
    assert result["actor"] == "Test Examiner"
    assert result["handling_event_id"]


def test_handling_event_id_is_unique(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    first = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="RECEIVED",
        actor="Examiner A",
    )

    second = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="ACCESSED",
        actor="Examiner B",
    )

    assert first["handling_event_id"] != second["handling_event_id"]


def test_event_type_is_normalized(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    result = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="received",
        actor="Test Examiner",
    )

    assert result["event_type"] == "RECEIVED"


def test_custody_transfer_is_recorded(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    result = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="TRANSFERRED",
        actor="Test Examiner",
        previous_custodian="Examiner A",
        new_custodian="Examiner B",
        location="Forensic Lab",
        reason="Documented custody transfer",
    )

    assert result["previous_custodian"] == "Examiner A"
    assert result["new_custodian"] == "Examiner B"
    assert result["location"] == "Forensic Lab"


def test_event_timestamp_is_normalized_to_utc(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    result = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="EXAMINED",
        actor="Test Examiner",
        event_timestamp_utc="2026-11-20T10:00:00+00:00",
    )

    parsed = datetime.fromisoformat(
        result["event_timestamp_utc"]
    )

    assert parsed.utcoffset().total_seconds() == 0


def test_naive_event_timestamp_is_rejected(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    with pytest.raises(ValueError, match="timezone"):
        record_handling_event(
            db_path=db_path,
            evidence_id=evidence["evidence_id"],
            event_type="EXAMINED",
            actor="Test Examiner",
            event_timestamp_utc="2026-11-20T10:00:00",
        )


def test_non_utc_event_timestamp_is_rejected(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    with pytest.raises(ValueError, match="UTC"):
        record_handling_event(
            db_path=db_path,
            evidence_id=evidence["evidence_id"],
            event_type="EXAMINED",
            actor="Test Examiner",
            event_timestamp_utc="2026-11-20T10:00:00+05:30",
        )


def test_invalid_event_type_is_rejected(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    with pytest.raises(ValueError, match="Unsupported"):
        record_handling_event(
            db_path=db_path,
            evidence_id=evidence["evidence_id"],
            event_type="INVALID_EVENT",
            actor="Test Examiner",
        )


def test_unregistered_evidence_is_rejected(tmp_path):
    db_path = create_test_database(tmp_path)

    with pytest.raises(ValueError, match="not registered"):
        record_handling_event(
            db_path=db_path,
            evidence_id="UNKNOWN-EVIDENCE",
            event_type="RECEIVED",
            actor="Test Examiner",
        )


def test_missing_actor_is_rejected(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    with pytest.raises(ValueError, match="Actor"):
        record_handling_event(
            db_path=db_path,
            evidence_id=evidence["evidence_id"],
            event_type="RECEIVED",
            actor="",
        )


def test_details_are_saved_as_json(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    result = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="OTHER",
        actor="Test Examiner",
        details={
            "description": "Synthetic evidence examination",
            "method": "Visual inspection",
        },
    )

    saved_details = json.loads(result["details_json"])

    assert saved_details["description"] == (
        "Synthetic evidence examination"
    )
    assert saved_details["method"] == "Visual inspection"


def test_invalid_details_are_rejected(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    with pytest.raises(ValueError, match="JSON-serializable"):
        record_handling_event(
            db_path=db_path,
            evidence_id=evidence["evidence_id"],
            event_type="OTHER",
            actor="Test Examiner",
            details={"invalid": object()},
        )


def test_handling_history_is_retrieved(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="RECEIVED",
        actor="Examiner A",
    )

    record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="EXAMINED",
        actor="Examiner B",
    )

    history = get_handling_history(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
    )

    assert len(history) == 2


def test_handling_history_pagination(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    for event_type in ["RECEIVED", "ACCESSED", "EXAMINED"]:
        record_handling_event(
            db_path=db_path,
            evidence_id=evidence["evidence_id"],
            event_type=event_type,
            actor="Test Examiner",
        )

    first_page = get_handling_history(
        db_path,
        evidence["evidence_id"],
        limit=2,
        offset=0,
    )

    second_page = get_handling_history(
        db_path,
        evidence["evidence_id"],
        limit=2,
        offset=2,
    )

    assert len(first_page) == 2
    assert len(second_page) == 1


def test_invalid_pagination_is_rejected(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    with pytest.raises(ValueError, match="positive integer"):
        get_handling_history(
            db_path,
            evidence["evidence_id"],
            limit=0,
        )

    with pytest.raises(ValueError, match="non-negative integer"):
        get_handling_history(
            db_path,
            evidence["evidence_id"],
            offset=-1,
        )


def test_handling_events_cannot_be_updated(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    result = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="RECEIVED",
        actor="Test Examiner",
    )

    connection = sqlite3.connect(db_path)

    try:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="cannot be modified",
        ):
            connection.execute(
                """
                UPDATE evidence_handling_events
                SET actor = ?
                WHERE handling_event_id = ?
                """,
                ("Changed Examiner", result["handling_event_id"]),
            )
    finally:
        connection.close()


def test_handling_events_cannot_be_deleted(tmp_path):
    db_path, _, evidence = create_registered_test_case(tmp_path)

    result = record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="RECEIVED",
        actor="Test Examiner",
    )

    connection = sqlite3.connect(db_path)

    try:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="cannot be deleted",
        ):
            connection.execute(
                """
                DELETE FROM evidence_handling_events
                WHERE handling_event_id = ?
                """,
                (result["handling_event_id"],),
            )
    finally:
        connection.close()


def test_original_evidence_is_not_modified(tmp_path):
    db_path, evidence_path, evidence = create_registered_test_case(
        tmp_path
    )

    original_hash = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()

    record_handling_event(
        db_path=db_path,
        evidence_id=evidence["evidence_id"],
        event_type="EXAMINED",
        actor="Test Examiner",
    )

    final_hash = hashlib.sha256(
        evidence_path.read_bytes()
    ).hexdigest()

    assert final_hash == original_hash


def test_handling_history_is_isolated_by_evidence_id(tmp_path):
    db_path = create_test_database(tmp_path)

    first_path = tmp_path / "first.jpg"
    first_path.write_bytes(bytes.fromhex("FF D8 FF") + b"first")

    second_path = tmp_path / "second.jpg"
    second_path.write_bytes(bytes.fromhex("FF D8 FF") + b"second")

    first_evidence = register_test_evidence(db_path, first_path)
    second_evidence = register_test_evidence(db_path, second_path)

    record_handling_event(
        db_path=db_path,
        evidence_id=first_evidence["evidence_id"],
        event_type="RECEIVED",
        actor="Examiner A",
    )

    first_history = get_handling_history(
        db_path,
        first_evidence["evidence_id"],
    )

    second_history = get_handling_history(
        db_path,
        second_evidence["evidence_id"],
    )

    assert len(first_history) == 1
    assert len(second_history) == 0
