
from pathlib import Path


# Known file signatures (magic bytes)
FILE_SIGNATURES = {
    "JPEG": [bytes.fromhex("FF D8 FF")],
    "PNG": [bytes.fromhex("89 50 4E 47 0D 0A 1A 0A")],
    "PDF": [b"%PDF-"],
    "ZIP": [
        bytes.fromhex("50 4B 03 04"),
        bytes.fromhex("50 4B 05 06"),
        bytes.fromhex("50 4B 07 08"),
    ],
    "SQLite": [b"SQLite format 3\x00"],
    "GIF": [b"GIF87a", b"GIF89a"],
}


# Expected extensions for supported formats
EXPECTED_EXTENSIONS = {
    "JPEG": {".jpg", ".jpeg"},
    "PNG": {".png"},
    "PDF": {".pdf"},
    "ZIP": {".zip"},
    "SQLite": {".db", ".sqlite", ".sqlite3"},
    "GIF": {".gif"},
}


def identify_file_format(file_path: str | Path) -> str:
    """
    Identify a file using its internal binary signature.

    This function does not rely on the filename extension.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    with path.open("rb") as file:
        header = file.read(32)

    if not header:
        return "Empty"

    for file_format, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if header.startswith(signature):
                return file_format

    return "Unknown"


def check_extension_mismatch(file_path: str | Path) -> dict:
    """
    Compare the detected file format with its filename extension.

    Returns the detected format, extension and mismatch status.
    """

    path = Path(file_path)

    detected_format = identify_file_format(path)
    extension = path.suffix.lower()

    expected_extensions = EXPECTED_EXTENSIONS.get(
        detected_format, set()
    )

    mismatch = (
        detected_format not in {"Unknown", "Empty"}
        and extension not in expected_extensions
    )

    return {
        "filename": path.name,
        "detected_format": detected_format,
        "extension": extension,
        "extension_mismatch": mismatch,
    }
