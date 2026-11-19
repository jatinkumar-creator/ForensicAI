
import sqlite3
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """
    Create and return a SQLite database connection.

    Foreign-key enforcement is enabled for every connection.
    Rows can be accessed by column name.
    """

    path = Path(db_path)

    # Ensure the database directory exists.
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        path,
        timeout=5.0,
    )

    # Enable foreign-key enforcement.
    connection.execute("PRAGMA foreign_keys = ON")

    # Allow access to rows using column names.
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database(
    db_path: str | Path,
    schema_path: str | Path = DEFAULT_SCHEMA_PATH,
) -> None:
    """
    Initialize the SQLite database using schema.sql.

    Existing tables are preserved because the schema uses
    CREATE TABLE IF NOT EXISTS.
    """

    schema_file = Path(schema_path)

    if not schema_file.exists():
        raise FileNotFoundError(
            f"Database schema not found: {schema_file}"
        )

    if not schema_file.is_file():
        raise ValueError(
            f"Schema path is not a regular file: {schema_file}"
        )

    schema_sql = schema_file.read_text(encoding="utf-8")

    if not schema_sql.strip():
        raise ValueError("Database schema file is empty.")

    connection = get_connection(db_path)

    try:
        connection.executescript(schema_sql)
        connection.commit()

    except sqlite3.Error:
        connection.rollback()
        raise

    finally:
        connection.close()
