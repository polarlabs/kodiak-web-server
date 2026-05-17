--
-- Subject
-- Represents any entity which acts on Kodiak,
-- e.g. a user or an application.
--
-- Columns:
-- id: set automatically by the DB.
-- uuid: set by Kodiak on record creation.
-- name: defined by the user.
-- ts_created: timestamp of record's creation.
-- ts_updated: timestamp of record's last update.
--
CREATE TABLE IF NOT EXISTS subject (
    id INTEGER NOT NULL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    ts_created TEXT NOT NULL,
    ts_updated TEXT NOT NULL
) STRICT;

-- Use index created by SQLite for columns with UNIQUE constraints.
-- CREATE UNIQUE INDEX IF NOT EXISTS idx_subject_uuid ON subject (uuid);

-- Create an index on column "name".
CREATE INDEX IF NOT EXISTS idx_subject_name
ON subject (
    name
);
