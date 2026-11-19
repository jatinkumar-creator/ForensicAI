
from datetime import datetime
from uuid import UUID

import pytest

from app.evidence.processor import process_evidence


def test_process_jpeg_evidence(tmp_path):
    evidence_file = tmp_path / "photo.jpg"
    evidence_file.write_bytes(bytes.fromhex("FF D8 FF") + b"sample")

    result = process_evidence(evidence_file)

    assert result["filename"] == "photo.jpg"
    assert result["detected_format"] == "JPEG"
    assert result["file_size_bytes"] == evidence_file.stat().st_size
    assert result["extension_mismatch"] is False
    assert result["hash_algorithm"] == "SHA-256"
    assert len(result["calculated_sha256"]) == 64
    assert result["hash_status"] == "BASELINE_CREATED"
    assert result["processing_status"] == "COMPLETED"


def test_process_extension_mismatch(tmp_path):
    evidence_file = tmp_path / "photo.png"
    evidence_file.write_bytes(b"%PDF-1.7 sample")

    result = process_evidence(evidence_file)

    assert result["detected_format"] == "PDF"
    assert result["extension_mismatch"] is True


def test_process_unknown_file(tmp_path):
    evidence_file = tmp_path / "unknown.bin"
    evidence_file.write_bytes(b"unknown content")

    result = process_evidence(evidence_file)

    assert result["detected_format"] == "Unknown"
    assert result["processing_status"] == "COMPLETED"
    assert len(result["calculated_sha256"]) == 64


def test_process_empty_file(tmp_path):
    evidence_file = tmp_path / "empty.jpg"
    evidence_file.write_bytes(b"")

    result = process_evidence(evidence_file)

    assert result["detected_format"] == "Empty"
    assert result["file_size_bytes"] == 0
    assert len(result["calculated_sha256"]) == 64


def test_missing_evidence_file(tmp_path):
    evidence_file = tmp_path / "missing.jpg"

    with pytest.raises(FileNotFoundError):
        process_evidence(evidence_file)


def test_directory_as_evidence(tmp_path):
    with pytest.raises(ValueError):
        process_evidence(tmp_path)


def test_unique_evidence_ids(tmp_path):
    evidence_file = tmp_path / "sample.bin"
    evidence_file.write_bytes(b"sample")

    result1 = process_evidence(evidence_file)
    result2 = process_evidence(evidence_file)

    assert result1["evidence_id"] != result2["evidence_id"]

    # Both identifiers must be valid UUIDs.
    UUID(result1["evidence_id"])
    UUID(result2["evidence_id"])


def test_timestamp_is_utc(tmp_path):
    evidence_file = tmp_path / "sample.bin"
    evidence_file.write_bytes(b"sample")

    result = process_evidence(evidence_file)

    timestamp = datetime.fromisoformat(result["processed_at_utc"])

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset().total_seconds() == 0


def test_original_file_is_not_modified(tmp_path):
    evidence_file = tmp_path / "original.jpg"
    original_content = bytes.fromhex("FF D8 FF") + b"original evidence"
    evidence_file.write_bytes(original_content)

    process_evidence(evidence_file)

    assert evidence_file.read_bytes() == original_content
