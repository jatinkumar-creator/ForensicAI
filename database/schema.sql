
-- ForensicAI Evidence Registry
-- Database schema version 1.1

PRAGMA foreign_keys = ON;


-- 1. Evidence records
CREATE TABLE IF NOT EXISTS evidence_records (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT,

    filename TEXT NOT NULL,
    source_path TEXT NOT NULL,

    file_size_bytes INTEGER NOT NULL
        CHECK (file_size_bytes >= 0),

    detected_format TEXT NOT NULL,
    file_extension TEXT NOT NULL,

    extension_mismatch INTEGER NOT NULL
        CHECK (extension_mismatch IN (0, 1)),

    hash_algorithm TEXT NOT NULL
        CHECK (hash_algorithm = 'SHA-256'),

    baseline_sha256 TEXT NOT NULL
        CHECK (
            length(baseline_sha256) = 64
            AND baseline_sha256 NOT GLOB '*[^0-9a-fA-F]*'
        ),

    registered_at_utc TEXT NOT NULL,

    record_status TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (record_status IN ('ACTIVE', 'ARCHIVED')),

    -- Optional acquisition metadata
    acquisition_time_utc TEXT,
    acquisition_method TEXT,
    acquisition_tool TEXT,
    acquisition_tool_version TEXT,
    source_description TEXT,
    examiner_reference TEXT
);


-- 2. Verification history
CREATE TABLE IF NOT EXISTS verification_history (
    verification_id TEXT PRIMARY KEY,

    evidence_id TEXT NOT NULL,

    expected_sha256 TEXT NOT NULL
        CHECK (
            length(expected_sha256) = 64
            AND expected_sha256 NOT GLOB '*[^0-9a-fA-F]*'
        ),

    -- Provenance of the expected reference hash
    reference_source TEXT NOT NULL
        CHECK (
            reference_source IN (
                'REGISTERED_BASELINE',
                'ACQUISITION_RECORD',
                'EXAMINER_SUPPLIED',
                'OTHER',
                'UNSPECIFIED'
            )
        ),

    reference_description TEXT,

    observed_sha256 TEXT NOT NULL
        CHECK (
            length(observed_sha256) = 64
            AND observed_sha256 NOT GLOB '*[^0-9a-fA-F]*'
        ),

    verification_status TEXT NOT NULL
        CHECK (
            verification_status IN ('MATCH', 'MISMATCH')
        ),

    verified_at_utc TEXT NOT NULL,

    FOREIGN KEY (evidence_id)
        REFERENCES evidence_records(evidence_id)
        ON DELETE RESTRICT,

    CHECK (
        verification_status =
        CASE
            WHEN lower(expected_sha256) = lower(observed_sha256)
            THEN 'MATCH'
            ELSE 'MISMATCH'
        END
    )
);


-- 3. Audit history
CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id TEXT PRIMARY KEY,

    evidence_id TEXT NOT NULL,

    action TEXT NOT NULL,

    event_timestamp_utc TEXT NOT NULL,

    actor TEXT,

    details_json TEXT,

    FOREIGN KEY (evidence_id)
        REFERENCES evidence_records(evidence_id)
        ON DELETE RESTRICT
);


-- Indexes for common evidence lookups
CREATE INDEX IF NOT EXISTS idx_evidence_case_id
    ON evidence_records(case_id);

CREATE INDEX IF NOT EXISTS idx_evidence_registered_at
    ON evidence_records(registered_at_utc);

CREATE INDEX IF NOT EXISTS idx_verification_evidence_id
    ON verification_history(evidence_id);

CREATE INDEX IF NOT EXISTS idx_audit_evidence_id
    ON audit_logs(evidence_id);
