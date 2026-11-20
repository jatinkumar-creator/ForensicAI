
"""Record and retrieve append-only evidence handling events."""

import json
import sqlite3

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from database.connection import get_connection


ALLOWED_EVENT_TYPES = {
    "RECEIVED",
    "TRANSFERRED",
    "ACCESSED",
    "EXAMINED",
    "STORED",
    "RELEASED",
    "RETURNED",
    "ARCHIVED",
    "OTHER",
}


def _validate_text(value: str, field_name: str) -> str:
    """Validate a required non-empty text value."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string.")

    return value.strip()


def _validate_optional_text(
    value: str | None,
    field_name: str,
) -> str | None:
    """Validate an optional text value."""

    if value is None:
        return None

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string or None.")

    if not value.strip():
        raise ValueError(f"{field_name} cannot be empty.")

    return value.strip()


def _normalize_event_timestamp(
    value: str | None,
) -> str:
    """
    Validate an event timestamp and normalize it to UTC.

    If no timestamp is supplied, the current UTC time is used.
    Naive timestamps are rejected because their timezone is unknown.
    """

    if value is None:
        return datetime.now(timezone.utc).isoformat()

    if not isinstance(value, str):
        raise TypeError("Event timestamp must be a string or None.")

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(
            "Invalid event timestamp. Use ISO 8601 format."
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "Event timestamp must include a timezone."
        )

    if parsed.utcoffset().total_seconds() != 0:
        raise ValueError(
            "Event timestamp must use UTC."
        )

    return parsed.astimezone(timezone.utc).isoformat()


def record_handling_event(
    db_path: str | Path,
    evidence_id: str,
    event_type: str,
    actor: str,
    event_timestamp_utc: str | None = None,
    previous_custodian: str | None = None,
    new_custodian: str | None = None,
    location: str | None = None,
    reason: str | None = None,
    details: dict | None = None,
) -> dict:
    """
    Record a handling event for registered evidence.

    Events are append-only. The database triggers prevent
    ordinary UPDATE and DELETE operations.

    The event timestamp describes when the handling occurred.
    The recorded timestamp describes when this system recorded it.

    This function records examiner-supplied information.
    It does not independently prove that the described event occurred.
    """

    evidence_id = _validate_text(evidence_id, "Evidence ID")
    actor = _validate_text(actor, "Actor")

    if not isinstance(event_type, str):
        raise TypeError("Event type must be a string.")

    event_type = event_type.strip().upper()

    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError(
            f"Unsupported handling event type: {event_type}"
        )

    previous_custodian = _validate_optional_text(
        previous_custodian,
        "Previous custodian",
    )

    new_custodian = _validate_optional_text(
        new_custodian,
        "New custodian",
    )

    location = _validate_optional_text(location, "Location")
    reason = _validate_optional_text(reason, "Reason")

    if details is None:
        details = {}

    if not isinstance(details, dict):
        raise TypeError("Details must be a dictionary.")

    try:
        details_json = json.dumps(
            details,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Details must contain JSON-serializable values."
        ) from exc

    event_timestamp = _normalize_event_timestamp(
        event_timestamp_utc
    )

    recorded_timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    handling_event_id = str(uuid4())

    record = {
        "handling_event_id": handling_event_id,
        "evidence_id": evidence_id,
        "event_type": event_type,
        "event_timestamp_utc": event_timestamp,
        "recorded_at_utc": recorded_timestamp,
        "actor": actor,
        "previous_custodian": previous_custodian,
        "new_custodian": new_custodian,
        "location": location,
        "reason": reason,
        "details_json": details_json,
    }

    connection = get_connection(db_path)

    try:
        # Confirm that the evidence is registered.
        evidence = connection.execute(
            """
            SELECT evidence_id
            FROM evidence_records
            WHERE evidence_id = ?
            """,
            (evidence_id,),
        ).fetchone()

        if evidence is None:
            raise ValueError(
                f"Evidence ID is not registered: {evidence_id}"
            )

        # Insert a new handling event.
        connection.execute(
            """
            INSERT INTO evidence_handling_events (
                handling_event_id,
                evidence_id,
                event_type,
                event_timestamp_utc,
                recorded_at_utc,
                actor,
                previous_custodian,
                new_custodian,
                location,
                reason,
                details_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            tuple(record.values()),
        )

        connection.commit()

        return record

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_handling_history(
    db_path: str | Path,
    evidence_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """
    Retrieve handling history for one evidence ID.

    Results are ordered by event timestamp and recording time.
    Pagination is supported.
    """

    evidence_id = _validate_text(evidence_id, "Evidence ID")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise ValueError("Limit must be a positive integer.")

    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("Offset must be a non-negative integer.")

    connection = get_connection(db_path)

    try:
        rows = connection.execute(
            """
            SELECT *
            FROM evidence_handling_events
            WHERE evidence_id = ?
            ORDER BY
                event_timestamp_utc,
                recorded_at_utc,
                handling_event_id
            LIMIT ? OFFSET ?
            """,
            (evidence_id, limit, offset),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
