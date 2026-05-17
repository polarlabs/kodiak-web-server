--
-- Table migration_status reflects the migrations
-- the database is going through right now.
--
-- The record of a migration script is copied to
-- migration_history and subsequently deleted
-- from this table, as soon as its status is done,
-- aka it has a resolution.
--
-- v: Version
-- direction: up | down
-- rank: an integer,
-- filename: SQL script's filename
-- hash: sha256
-- status: created | running | done
-- resolution: succeeded | canceled | failed
-- progress: between 0 and 1 with 5 decimals (calculated as rank of script / power of set)
--   sqlx does not support DECIMAL for sqlite:
--   https://docs.rs/sqlx/latest/sqlx/sqlite/types/index.html#non-feature-numeric--rust_decimal--bigdecimal-support
-- tstamp: timestamp of record's last update
--
-- v + direction defines the set of migration scripts to execute
-- v + direction + rank defines the migration scripts' execution sequence
CREATE TABLE IF NOT EXISTS migration_status (
    id INTEGER NOT NULL PRIMARY KEY,
    driver TEXT NOT NULL,
    v TEXT NOT NULL,
    direction TEXT NOT NULL,
    rank INTEGER NOT NULL,
    filename TEXT NOT NULL,
    hash TEXT,
    status TEXT NOT NULL,
    resolution TEXT,
    progress TEXT NOT NULL,
    tstamp TEXT NOT NULL,
    UNIQUE(v, direction, rank, filename) ON CONFLICT REPLACE
) STRICT;
