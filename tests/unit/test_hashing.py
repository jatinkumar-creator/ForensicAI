
import hashlib
import pytest

from app.integrity.hashing import (
    calculate_sha256,
    verify_sha256,
)


def test_sha256_calculation(tmp_path):
    file_path = tmp_path / "evidence.txt"
    file_path.write_bytes(b"ForensicAI evidence")

    expected_hash = hashlib.sha256(
        b"ForensicAI evidence"
    ).hexdigest()

    assert calculate_sha256(file_path) == expected_hash


def test_integrity_match(tmp_path):
    file_path = tmp_path / "evidence.txt"
    file_path.write_bytes(b"Original evidence")

    original_hash = calculate_sha256(file_path)

    result = verify_sha256(file_path, original_hash)

    assert result["status"] == "MATCH"
    assert result["integrity_verified"] is True


def test_modified_file_detection(tmp_path):
    file_path = tmp_path / "evidence.txt"
    file_path.write_bytes(b"Original evidence")

    original_hash = calculate_sha256(file_path)

    file_path.write_bytes(b"Modified evidence")

    result = verify_sha256(file_path, original_hash)

    assert result["status"] == "MISMATCH"
    assert result["integrity_verified"] is False


def test_empty_file_hash(tmp_path):
    file_path = tmp_path / "empty.bin"
    file_path.write_bytes(b"")

    expected_hash = hashlib.sha256(b"").hexdigest()

    assert calculate_sha256(file_path) == expected_hash


def test_missing_file(tmp_path):
    file_path = tmp_path / "missing.bin"

    with pytest.raises(FileNotFoundError):
        calculate_sha256(file_path)


def test_chunk_processing(tmp_path):
    file_path = tmp_path / "large_test.bin"

    content = b"ForensicAI" * 10000
    file_path.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()

    actual_hash = calculate_sha256(
        file_path,
        chunk_size=1024
    )

    assert actual_hash == expected_hash


def test_invalid_chunk_size(tmp_path):
    file_path = tmp_path / "evidence.bin"
    file_path.write_bytes(b"Test data")

    with pytest.raises(ValueError):
        calculate_sha256(file_path, chunk_size=0)


def test_invalid_hash_length(tmp_path):
    file_path = tmp_path / "evidence.bin"
    file_path.write_bytes(b"Test data")

    with pytest.raises(ValueError):
        verify_sha256(file_path, "invalid")
