
import sqlite3

import pytest

from database.connection import get_connection, initialize_database
from app.cases.manager import (
    create_case,
    get_case,
    list_cases,
    close_case,
    reopen_case,
    get_case_events,
)


@pytest.fixture
def database(tmp_path):
    """Create a fresh temporary database for each test."""
    db_path = tmp_path / "forensicai_test.db"
    initialize_database(db_path)
    return db_path


def test_cases_table_exists(database):
    connection = get_connection(database)

    try:
        result = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = 'cases'
            """
        ).fetchone()

        assert result is not None
    finally:
        connection.close()


def test_case_events_table_exists(database):
    connection = get_connection(database)

    try:
        result = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table' AND name = 'case_events'
            """
        ).fetchone()

        assert result is not None
    finally:
        connection.close()


def test_case_events_cannot_be_updated(database):
    connection = get_connection(database)

    try:
        connection.execute(
            """
            INSERT INTO cases (
                case_id, title, status,
                created_at_utc, updated_at_utc
            )
            VALUES ('CASE-001', 'Test case', 'OPEN', '2026-01-01T00:00:00+00:00',
                    '2026-01-01T00:00:00+00:00')
            """
        )

        connection.execute(
            """
            INSERT INTO case_events (
                event_id, case_id, event_type,
                event_timestamp_utc, actor
            )
            VALUES (
                'EVENT-001', 'CASE-001', 'CREATED',
                '2026-01-01T00:00:00+00:00', 'tester'
            )
            """
        )
        connection.commit()

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE case_events
                SET actor = 'changed'
                WHERE event_id = 'EVENT-001'
                """
            )
    finally:
        connection.close()


def test_case_events_cannot_be_deleted(database):
    connection = get_connection(database)

    try:
        connection.execute(
            """
            INSERT INTO cases (
                case_id, title, status,
                created_at_utc, updated_at_utc
            )
            VALUES ('CASE-002', 'Test case', 'OPEN', '2026-01-01T00:00:00+00:00',
                    '2026-01-01T00:00:00+00:00')
            """
        )

        connection.execute(
            """
            INSERT INTO case_events (
                event_id, case_id, event_type,
                event_timestamp_utc, actor
            )
            VALUES (
                'EVENT-002', 'CASE-002', 'CREATED',
                '2026-01-01T00:00:00+00:00', 'tester'
            )
            """
        )
        connection.commit()

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                DELETE FROM case_events
                WHERE event_id = 'EVENT-002'
                """
            )
    finally:
        connection.close()


def test_case_rejects_invalid_status(database):
    connection = get_connection(database)

    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO cases (
                    case_id, title, status,
                    created_at_utc, updated_at_utc
                )
                VALUES (
                    'CASE-003', 'Invalid case', 'PENDING',
                    '2026-01-01T00:00:00+00:00',
                    '2026-01-01T00:00:00+00:00'
                )
                """
            )
    finally:
        connection.close()

def test_create_case_successfully(database):
    case = create_case(
        database,
        title="Mobile Forensics Investigation",
        description="Synthetic investigation case.",
        actor="Examiner",
    )

    assert case["title"] == "Mobile Forensics Investigation"
    assert case["status"] == "OPEN"
    assert case["description"] == "Synthetic investigation case."
    assert case["created_by"] == "Examiner"
    assert case["closed_at_utc"] is None
    assert case["case_id"]


def test_created_case_has_creation_event(database):
    case = create_case(
        database,
        title="Event Test Case",
        actor="Examiner",
    )

    events = get_case_events(database, case["case_id"])

    assert len(events) == 1
    assert events[0]["event_type"] == "CREATED"
    assert events[0]["actor"] == "Examiner"


def test_get_case_returns_none_for_unknown_id(database):
    assert get_case(database, "UNKNOWN-CASE") is None


def test_list_cases_and_filter_by_status(database):
    first = create_case(database, "Open Case")
    second = create_case(database, "Case to Close")

    close_case(database, second["case_id"], "Examiner")

    open_cases = list_cases(database, status="OPEN")
    closed_cases = list_cases(database, status="CLOSED")

    assert any(
        case["case_id"] == first["case_id"]
        for case in open_cases
    )

    assert len(closed_cases) == 1
    assert closed_cases[0]["case_id"] == second["case_id"]


def test_close_case_successfully(database):
    case = create_case(database, "Closure Test")

    closed_case = close_case(
        database,
        case["case_id"],
        "Examiner",
    )

    assert closed_case["status"] == "CLOSED"
    assert closed_case["closed_at_utc"] is not None


def test_reopen_case_successfully(database):
    case = create_case(database, "Reopening Test")

    close_case(database, case["case_id"], "Examiner")

    reopened_case = reopen_case(
        database,
        case["case_id"],
        "Senior Examiner",
    )

    assert reopened_case["status"] == "OPEN"
    assert reopened_case["closed_at_utc"] is None


def test_lifecycle_events_are_preserved(database):
    case = create_case(database, "Lifecycle History")

    close_case(database, case["case_id"], "Examiner")
    reopen_case(database, case["case_id"], "Senior Examiner")

    events = get_case_events(database, case["case_id"])

    event_types = [event["event_type"] for event in events]

    assert event_types == [
        "CREATED",
        "CLOSED",
        "REOPENED",
    ]


def test_open_case_cannot_be_closed_twice(database):
    case = create_case(database, "Repeated Closure")

    close_case(database, case["case_id"], "Examiner")

    with pytest.raises(ValueError):
        close_case(database, case["case_id"], "Examiner")


def test_closed_case_cannot_be_reopened_twice(database):
    case = create_case(database, "Repeated Reopening")

    with pytest.raises(ValueError):
        reopen_case(database, case["case_id"], "Examiner")


def test_missing_case_cannot_be_closed(database):
    with pytest.raises(ValueError):
        close_case(database, "UNKNOWN-CASE", "Examiner")


def test_empty_case_title_is_rejected(database):
    with pytest.raises(ValueError):
        create_case(database, "   ")


def test_invalid_status_filter_is_rejected(database):
    with pytest.raises(ValueError):
        list_cases(database, status="PENDING")


def test_invalid_pagination_is_rejected(database):
    with pytest.raises(ValueError):
        list_cases(database, limit=0)

    with pytest.raises(ValueError):
        list_cases(database, offset=-1)
