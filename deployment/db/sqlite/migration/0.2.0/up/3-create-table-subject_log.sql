--
-- Log for all changes to Subjects, including
-- created, changed, archived and so on.
-- (see table actions for further details)
--
-- Foreign key constrains:
-- - subject (id):
--   -> ON UPDATE RESTRICT: refuse to change id
--      if subject_log has a record with this id as foreign key
--   -> ON DELETE RESTRICT: refuse to delete an subject
--      which is in use by a subject_log
--
-- - action (id):
--   -> ON UPDATE RESTRICT: refuse to change id
--      if subject_log has a record with this id as foreign key
--   -> ON DELETE RESTRICT: refuse to delete an action
--      which is in use by a subject_log
--
CREATE TABLE IF NOT EXISTS subject_log (
    id INTEGER NOT NULL PRIMARY KEY,
    note TEXT,
    prev TEXT,
    post TEXT,
    ts TEXT NOT NULL,
    subject_id INTEGER NOT NULL,
    action_id INTEGER NOT NULL,
    FOREIGN KEY (
        subject_id
    ) REFERENCES subject (id) ON UPDATE RESTRICT ON DELETE RESTRICT,
    FOREIGN KEY (
        action_id
    ) REFERENCES action (id) ON UPDATE RESTRICT ON DELETE RESTRICT
) STRICT;

-- Create indexes for foreign key columns.
CREATE INDEX IF NOT EXISTS
idx_subject_log_subject
ON subject_log (
    subject_id
);
CREATE INDEX IF NOT EXISTS
idx_subject_log_action
ON subject_log (
    action_id
);
