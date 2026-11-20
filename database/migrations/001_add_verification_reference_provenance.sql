
-- Migration 001
-- Add reference provenance to verification history.
--
-- Intended for databases created using the previous schema.
-- Do not run against a database that already has these columns.

ALTER TABLE verification_history
ADD COLUMN reference_source TEXT NOT NULL
DEFAULT 'UNSPECIFIED'
CHECK (
    reference_source IN (
        'REGISTERED_BASELINE',
        'ACQUISITION_RECORD',
        'EXAMINER_SUPPLIED',
        'OTHER',
        'UNSPECIFIED'
    )
);

ALTER TABLE verification_history
ADD COLUMN reference_description TEXT;
