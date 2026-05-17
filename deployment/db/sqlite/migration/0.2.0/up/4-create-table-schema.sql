--
-- Schema
-- Represents the top-level in application's entity hierarchy.
-- Allows to handle multiple use case within the same
-- application instance.
--
-- Columns:
-- id: used in relations to other tables, set automatically by the database.
-- uuid: globally unique identifier, set by application on creation.
-- name: locally unique identifier, set by the user.
-- ts_created: timestamp of record's creation.
-- ts_updated: timestamp of record's last update, might be NULL, i.e. schema was never updated.
--
CREATE TABLE IF NOT EXISTS schema (
    id INTEGER NOT NULL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL UNIQUE,
    ts_created TEXT NOT NULL,
    ts_updated TEXT
) STRICT;

-- Use index created by SQLite for columns with UNIQUE constraints.
-- CREATE UNIQUE INDEX IF NOT EXISTS idx_schema_uuid ON schema (uuid);

-- Create an index on column "name".
CREATE INDEX IF NOT EXISTS idx_schema_name
ON schema (
    name
);
