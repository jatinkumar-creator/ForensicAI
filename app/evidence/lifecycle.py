
"""Orchestrate evidence processing, registration, and verification."""

import re
from pathlib import Path

from app.evidence.processor import process_evidence
from app.evidence.registry import register_evidence
from app.evidence.verification import (
    verify_evidence,
    get_verification_history,
)


ALLOWED_REFERENCE_SOURCES = {
    "REGISTERED_BASELINE",
    "ACQUISITION_RECORD",
    "EXAMINER_SUPPLIED",
    "OTHER",
}


def _validate_lifecycle_inputs(
    reference_source: str,
    expected_sha256: str | None,
    reference_description: str | None,
    actor: str | None,
) -> None:
    """Validate verification inputs before registering evidence."""

    if reference_source not in ALLOWED_REFERENCE_SOURCES:
        raise ValueError(
            f"Unsupported reference source: {reference_source}"
        )

    if reference_source == "REGISTERED_BASELINE":
        if expected_sha256 is not None:
            raise ValueError(
                "Do not supply expected_sha256 when using "
                "REGISTERED_BASELINE."
            )
    else:
        if not isinstance(expected_sha256, str):
            raise ValueError(
                "An expected SHA-256 hash is required "
                "for external reference sources."
            )

        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
            raise ValueError("Invalid SHA-256 hash.")

        if (
            not isinstance(reference_description, str)
            or not reference_description.strip()
        ):
            raise ValueError(
                "A reference description is required "
                "for external reference sources."
            )

    if actor is not None:
        if not isinstance(actor, str) or not actor.strip():
            raise ValueError("Actor must be a non-empty string.")


def register_and_verify_evidence(
    db_path: str | Path,
    source_path: str | Path,
    case_id: str | None = None,
    acquisition_metadata: dict | None = None,
    reference_source: str = "REGISTERED_BASELINE",
    expected_sha256: str | None = None,
    reference_description: str | None = None,
    actor: str | None = None,
) -> dict:
    """
    Process, register, and verify one evidence file.

    Registration and verification are separate database
    transactions. If verification fails after registration,
    the registered evidence record remains preserved.

    A MISMATCH is a completed verification result, not
    an exception.

    Returns:
        A dictionary containing the processing record,
        registered evidence record, verification result,
        and verification history.
    """

    # Validate verification configuration before any
    # evidence processing or database registration.
    _validate_lifecycle_inputs(
        reference_source=reference_source,
        expected_sha256=expected_sha256,
        reference_description=reference_description,
        actor=actor,
    )

    # Step 1: Process the source evidence.
    processed_record = process_evidence(source_path)

    # Step 2: Register the evidence.
    # The registry independently revalidates the source hash.
    registered_record = register_evidence(
        db_path=db_path,
        processed_record=processed_record,
        source_path=source_path,
        case_id=case_id,
        acquisition_metadata=acquisition_metadata,
    )

    # Step 3: Verify the registered evidence.
    # Exceptions are deliberately propagated. Registration
    # remains committed if verification cannot complete.
    verification_record = verify_evidence(
        db_path=db_path,
        evidence_id=registered_record["evidence_id"],
        reference_source=reference_source,
        expected_sha256=expected_sha256,
        reference_description=reference_description,
        actor=actor,
    )

    # Step 4: Retrieve the persisted verification history.
    history = get_verification_history(
        db_path=db_path,
        evidence_id=registered_record["evidence_id"],
    )

    return {
        "lifecycle_status": "COMPLETED",
        "processing_record": processed_record,
        "evidence_record": registered_record,
        "verification": verification_record,
        "verification_history": history,
    }
