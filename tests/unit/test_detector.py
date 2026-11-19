
import pytest

from app.ingestion.detector import (
    identify_file_format,
    check_extension_mismatch,
)


def test_identify_jpeg(tmp_path):
    file_path = tmp_path / "image.jpg"
    file_path.write_bytes(
        bytes.fromhex("FF D8 FF") + b"TEST DATA"
    )

    assert identify_file_format(file_path) == "JPEG"


def test_identify_pdf(tmp_path):
    file_path = tmp_path / "document.pdf"
    file_path.write_bytes(b"%PDF-TEST DATA")

    assert identify_file_format(file_path) == "PDF"


def test_identify_unknown(tmp_path):
    file_path = tmp_path / "unknown.bin"
    file_path.write_bytes(b"UNKNOWN DATA")

    assert identify_file_format(file_path) == "Unknown"


def test_empty_file(tmp_path):
    file_path = tmp_path / "empty.dat"
    file_path.write_bytes(b"")

    assert identify_file_format(file_path) == "Empty"


def test_extension_mismatch(tmp_path):
    file_path = tmp_path / "image.pdf"
    file_path.write_bytes(
        bytes.fromhex("FF D8 FF") + b"JPEG TEST DATA"
    )

    result = check_extension_mismatch(file_path)

    assert result["detected_format"] == "JPEG"
    assert result["extension_mismatch"] is True


def test_missing_file(tmp_path):
    file_path = tmp_path / "missing.jpg"

    with pytest.raises(FileNotFoundError):
        identify_file_format(file_path)
