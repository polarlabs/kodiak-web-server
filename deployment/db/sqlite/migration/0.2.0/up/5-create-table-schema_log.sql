--
-- Log for all changes to Schemas, including
-- created, changed, archived and so on.
-- (see table actions for further details)
--
-- Foreign key constrains:
-- - subject (id):
--   -> ON UPDATE RESTRICT: refuse to change id
--      if schema_log has a record with this id as foreign key
--   -> ON DELETE RESTRICT: refuse to delete an subject
--      which is in use by a schema_log
--
-- - action (id):
--   -> ON UPDATE RESTRICT: refuse to change id
--      if schema_log has a record with this id as foreign key
--   -> ON DELETE RESTRICT: refuse to delete an action
--      which is in use by a schema_log
--
CREATE TABLE IF NOT EXISTS schema_log (
    id INTEGER NOT NULL PRIMARY KEY,
    note TEXT,
    prev TEXT,
    post TEXT,
    ts TEXT NOT NULL,
    schema_id INTEGER NOT NULL,
    action_id INTEGER NOT NULL,
    FOREIGN KEY (
        schema_id
    ) REFERENCES schema (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (
        action_id
    ) REFERENCES action (id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

-- Create indexes for foreign key columns.
CREATE INDEX IF NOT EXISTS
idx_schema_log_schema
ON schema_log (
    schema_id
);
CREATE INDEX IF NOT EXISTS
idx_schema_log_action
ON schema_log (
    action_id
);
