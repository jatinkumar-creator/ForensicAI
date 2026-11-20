
"""Case-aware evidence intake workflow."""

from pathlib import Path

from app.cases.manager import get_case
from app.evidence.processor import process_evidence
from app.evidence.registry import register_evidence


def intake_evidence(
    db_path: str | Path,
    source_path: str | Path,
    case_id: str,
    acquisition_metadata: dict | None = None,
) -> dict:
    """
    Process and register evidence against an existing open case.

    The original evidence file is not intentionally modified.
    The existing processor and registry perform file processing
    and source-file revalidation.
    """

    if not isinstance(case_id, str):
        raise TypeError("Case ID must be a string.")

    case_id = case_id.strip()

    if not case_id:
        raise ValueError("Case ID cannot be empty.")

    # Step 1: Confirm that the case exists.
    case = get_case(db_path, case_id)

    if case is None:
        raise ValueError(f"Case not found: {case_id}")

    # Step 2: Only open cases can receive new evidence.
    if case["status"] != "OPEN":
        raise ValueError(
            f"Evidence cannot be registered to a "
            f"case with status: {case['status']}"
        )

    # Step 3: Process the source evidence.
    processed_record = process_evidence(source_path)

    # Step 4: Register it and associate it with the case.
    registered_record = register_evidence(
        db_path=db_path,
        processed_record=processed_record,
        source_path=source_path,
        case_id=case_id,
        acquisition_metadata=acquisition_metadata,
    )

    return registered_record
