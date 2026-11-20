
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


-- 4. Evidence handling history
-- Records documented custody and handling events.
-- Events are append-only: corrections must be recorded
-- as new events rather than modifying existing records.

CREATE TABLE IF NOT EXISTS evidence_handling_events (
    handling_event_id TEXT PRIMARY KEY,

    evidence_id TEXT NOT NULL,

    event_type TEXT NOT NULL
        CHECK (
            event_type IN (
                'RECEIVED',
                'TRANSFERRED',
                'ACCESSED',
                'EXAMINED',
                'STORED',
                'RELEASED',
                'RETURNED',
                'ARCHIVED',
                'OTHER'
            )
        ),

    event_timestamp_utc TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL,

    actor TEXT NOT NULL,

    previous_custodian TEXT,
    new_custodian TEXT,

    location TEXT,
    reason TEXT,
    details_json TEXT,

    FOREIGN KEY (evidence_id)
        REFERENCES evidence_records(evidence_id)
        ON DELETE RESTRICT
);

-- Indexes for handling history lookups.
CREATE INDEX IF NOT EXISTS idx_handling_evidence_id
    ON evidence_handling_events(evidence_id);

CREATE INDEX IF NOT EXISTS idx_handling_event_timestamp
    ON evidence_handling_events(event_timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_handling_event_type
    ON evidence_handling_events(event_type);

-- Prevent modification or deletion of recorded events.
-- Corrections must be entered as new events.

CREATE TRIGGER IF NOT EXISTS prevent_handling_event_update
BEFORE UPDATE ON evidence_handling_events
BEGIN
    SELECT RAISE(
        ABORT,
        'Evidence handling events cannot be modified.'
    );
END;

CREATE TRIGGER IF NOT EXISTS prevent_handling_event_delete
BEFORE DELETE ON evidence_handling_events
BEGIN
    SELECT RAISE(
        ABORT,
        'Evidence handling events cannot be deleted.'
    );
END;


-- ============================================================
-- 5. Case Management
-- ============================================================

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'CLOSED')),
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    closed_at_utc TEXT,
    created_by TEXT,

    CHECK (
        (status = 'OPEN' AND closed_at_utc IS NULL)
        OR
        (status = 'CLOSED' AND closed_at_utc IS NOT NULL)
    )
);

-- Index for case status and creation-date lookups.
CREATE INDEX IF NOT EXISTS idx_cases_status
    ON cases(status);

CREATE INDEX IF NOT EXISTS idx_cases_created_at
    ON cases(created_at_utc);


-- ============================================================
-- 6. Case Activity History
-- ============================================================

CREATE TABLE IF NOT EXISTS case_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    event_type TEXT NOT NULL
        CHECK (
            event_type IN (
                'CREATED',
                'UPDATED',
                'CLOSED',
                'REOPENED'
            )
        ),
    event_timestamp_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    details_json TEXT,

    FOREIGN KEY (case_id)
        REFERENCES cases(case_id)
        ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_case_events_case_id
    ON case_events(case_id);

CREATE INDEX IF NOT EXISTS idx_case_events_timestamp
    ON case_events(event_timestamp_utc);


-- ============================================================
-- 7. Preserve Existing Case References
-- ============================================================
-- Existing evidence records may already contain case IDs.
-- Backfill those IDs instead of losing their associations.

INSERT OR IGNORE INTO cases (
    case_id,
    title,
    description,
    status,
    created_at_utc,
    updated_at_utc
)
SELECT
    case_id,
    'Legacy case ' || case_id,
    'Automatically preserved from existing evidence records.',
    'OPEN',
    MIN(registered_at_utc),
    MIN(registered_at_utc)
FROM evidence_records
WHERE case_id IS NOT NULL
  AND TRIM(case_id) <> ''
GROUP BY case_id;


-- ============================================================
-- 8. Protect Append-Only Case Activity History
-- ============================================================

CREATE TRIGGER IF NOT EXISTS prevent_case_event_update
BEFORE UPDATE ON case_events
BEGIN
    SELECT RAISE(
        ABORT,
        'Case events cannot be modified. Record a new event instead.'
    );
END;

CREATE TRIGGER IF NOT EXISTS prevent_case_event_delete
BEFORE DELETE ON case_events
BEGIN
    SELECT RAISE(
        ABORT,
        'Case events cannot be deleted.'
    );
END;
