--
-- Table migration_history reflects the migrations
-- the database went through in the past by storing
-- copies of records from migration_status.
--
-- The record of a migration script is copied as soon
-- as its status is done, aka it has a resolution.
--
CREATE TABLE IF NOT EXISTS migration_history (
    id INTEGER NOT NULL PRIMARY KEY,
    driver TEXT NOT NULL,
    v TEXT NOT NULL,
    direction TEXT NOT NULL,
    rank INTEGER NOT NULL,
    filename TEXT NOT NULL,
    hash TEXT,
    status TEXT NOT NULL,
    resolution TEXT NOT NULL,
    tstamp TEXT NOT NULL
) STRICT;
