
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from database.connection import get_connection


VALID_CASE_STATUSES = {"OPEN", "CLOSED"}


def _utc_now() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _validate_text(value: str, field_name: str) -> str:
    """Validate and normalize required text values."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")

    return value.strip()


def _record_case_event(
    connection,
    case_id: str,
    event_type: str,
    actor: str,
    timestamp: str,
    details: dict | None = None,
) -> None:
    """Insert an append-only case activity event."""
    connection.execute(
        """
        INSERT INTO case_events (
            event_id,
            case_id,
            event_type,
            event_timestamp_utc,
            actor,
            details_json
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid4()),
            case_id,
            event_type,
            timestamp,
            actor,
            json.dumps(details or {}, sort_keys=True),
        ),
    )


def create_case(
    db_path: str | Path,
    title: str,
    description: str | None = None,
    actor: str = "SYSTEM",
) -> dict:
    """Create a new case and record its creation event."""
    title = _validate_text(title, "Case title")
    actor = _validate_text(actor, "Actor")

    if description is not None:
        if not isinstance(description, str):
            raise TypeError("Description must be a string or None.")
        description = description.strip() or None

    timestamp = _utc_now()
    case_id = str(uuid4())

    connection = get_connection(db_path)

    try:
        with connection:
            connection.execute(
                """
                INSERT INTO cases (
                    case_id,
                    title,
                    description,
                    status,
                    created_at_utc,
                    updated_at_utc,
                    closed_at_utc,
                    created_by
                )
                VALUES (?, ?, ?, 'OPEN', ?, ?, NULL, ?)
                """,
                (
                    case_id,
                    title,
                    description,
                    timestamp,
                    timestamp,
                    actor,
                ),
            )

            _record_case_event(
                connection=connection,
                case_id=case_id,
                event_type="CREATED",
                actor=actor,
                timestamp=timestamp,
                details={"title": title},
            )

        return get_case(db_path, case_id)

    finally:
        connection.close()


def get_case(
    db_path: str | Path,
    case_id: str,
) -> dict | None:
    """Retrieve one case by its ID."""
    case_id = _validate_text(case_id, "Case ID")
    connection = get_connection(db_path)

    try:
        row = connection.execute(
            """
            SELECT *
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        return dict(row) if row is not None else None

    finally:
        connection.close()


def list_cases(
    db_path: str | Path,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """List cases with optional status filtering and pagination."""
    if status is not None:
        if not isinstance(status, str):
            raise TypeError("Status must be a string or None.")

        status = status.upper()

        if status not in VALID_CASE_STATUSES:
            raise ValueError("Status must be OPEN or CLOSED.")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("Limit must be a positive integer.")

    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("Offset must be a non-negative integer.")

    connection = get_connection(db_path)

    try:
        if status is None:
            rows = connection.execute(
                """
                SELECT *
                FROM cases
                ORDER BY created_at_utc DESC, case_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT *
                FROM cases
                WHERE status = ?
                ORDER BY created_at_utc DESC, case_id
                LIMIT ? OFFSET ?
                """,
                (status, limit, offset),
            ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def close_case(
    db_path: str | Path,
    case_id: str,
    actor: str,
) -> dict:
    """Close an open case and record the lifecycle event."""
    case_id = _validate_text(case_id, "Case ID")
    actor = _validate_text(actor, "Actor")
    timestamp = _utc_now()

    connection = get_connection(db_path)

    try:
        with connection:
            row = connection.execute(
                """
                SELECT status
                FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()

            if row is None:
                raise ValueError(f"Case not found: {case_id}")

            if row["status"] != "OPEN":
                raise ValueError("Only an open case can be closed.")

            connection.execute(
                """
                UPDATE cases
                SET status = 'CLOSED',
                    updated_at_utc = ?,
                    closed_at_utc = ?
                WHERE case_id = ?
                """,
                (timestamp, timestamp, case_id),
            )

            _record_case_event(
                connection=connection,
                case_id=case_id,
                event_type="CLOSED",
                actor=actor,
                timestamp=timestamp,
            )

        return get_case(db_path, case_id)

    finally:
        connection.close()


def reopen_case(
    db_path: str | Path,
    case_id: str,
    actor: str,
) -> dict:
    """Reopen a closed case and record the lifecycle event."""
    case_id = _validate_text(case_id, "Case ID")
    actor = _validate_text(actor, "Actor")
    timestamp = _utc_now()

    connection = get_connection(db_path)

    try:
        with connection:
            row = connection.execute(
                """
                SELECT status
                FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            ).fetchone()

            if row is None:
                raise ValueError(f"Case not found: {case_id}")

            if row["status"] != "CLOSED":
                raise ValueError("Only a closed case can be reopened.")

            connection.execute(
                """
                UPDATE cases
                SET status = 'OPEN',
                    updated_at_utc = ?,
                    closed_at_utc = NULL
                WHERE case_id = ?
                """,
                (timestamp, case_id),
            )

            _record_case_event(
                connection=connection,
                case_id=case_id,
                event_type="REOPENED",
                actor=actor,
                timestamp=timestamp,
            )

        return get_case(db_path, case_id)

    finally:
        connection.close()


def get_case_events(
    db_path: str | Path,
    case_id: str,
) -> list[dict]:
    """Retrieve the append-only activity history for one case."""
    case_id = _validate_text(case_id, "Case ID")
    connection = get_connection(db_path)

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM case_events
            WHERE case_id = ?
            ORDER BY event_timestamp_utc, event_id
            """,
            (case_id,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
