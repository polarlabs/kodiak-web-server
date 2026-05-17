--
-- Action
-- Stores actions used by Kodiak e.g. in its internal `*_log` tables.
--
CREATE TABLE IF NOT EXISTS action (
    id INTEGER NOT NULL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
) STRICT;

-- Use index created by SQLite for columns with UNIQUE constraints.
-- CREATE UNIQUE INDEX IF NOT EXISTS idx_action_name ON action (name);

--
-- Constants
--
INSERT OR IGNORE INTO action (name)
VALUES ('created'), ('changed'), ('archived'), ('deleted'), ('restored');
