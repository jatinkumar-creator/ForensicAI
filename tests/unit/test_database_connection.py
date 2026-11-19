
import sqlite3

import pytest

from database.connection import (
    get_connection,
    initialize_database,
)


def test_initialize_database_creates_tables(tmp_path):
    db_path = tmp_path / "forensicai.db"

    initialize_database(db_path)

    connection = get_connection(db_path)

    try:
        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            """
        ).fetchall()

        table_names = {row["name"] for row in tables}

        assert "evidence_records" in table_names
        assert "verification_history" in table_names
        assert "audit_logs" in table_names

    finally:
        connection.close()


def test_initialize_database_creates_parent_directory(tmp_path):
    db_path = tmp_path / "nested" / "data" / "forensicai.db"

    initialize_database(db_path)

    assert db_path.exists()


def test_foreign_keys_are_enabled(tmp_path):
    db_path = tmp_path / "forensicai.db"

    connection = get_connection(db_path)

    try:
        result = connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()

        assert result[0] == 1

    finally:
        connection.close()


def test_connection_uses_sqlite_row_factory(tmp_path):
    db_path = tmp_path / "forensicai.db"

    connection = get_connection(db_path)

    try:
        assert connection.row_factory is sqlite3.Row

    finally:
        connection.close()


def test_missing_schema_raises_error(tmp_path):
    db_path = tmp_path / "forensicai.db"
    schema_path = tmp_path / "missing_schema.sql"

    with pytest.raises(FileNotFoundError):
        initialize_database(db_path, schema_path)


def test_empty_schema_raises_error(tmp_path):
    db_path = tmp_path / "forensicai.db"
    schema_path = tmp_path / "empty_schema.sql"

    schema_path.write_text("", encoding="utf-8")

    with pytest.raises(ValueError):
        initialize_database(db_path, schema_path)


def test_database_schema_creates_indexes(tmp_path):
    db_path = tmp_path / "forensicai.db"

    initialize_database(db_path)

    connection = get_connection(db_path)

    try:
        indexes = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
            """
        ).fetchall()

        index_names = {row["name"] for row in indexes}

        assert "idx_evidence_case_id" in index_names
        assert "idx_evidence_registered_at" in index_names
        assert "idx_verification_evidence_id" in index_names
        assert "idx_audit_evidence_id" in index_names

    finally:
        connection.close()


def test_initialize_database_is_repeatable(tmp_path):
    db_path = tmp_path / "forensicai.db"

    initialize_database(db_path)
    initialize_database(db_path)

    connection = get_connection(db_path)

    try:
        result = connection.execute(
            """
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = 'table'
            AND name IN (
                'evidence_records',
                'verification_history',
                'audit_logs'
            )
            """
        ).fetchone()

        assert result[0] == 3

    finally:
        connection.close()
