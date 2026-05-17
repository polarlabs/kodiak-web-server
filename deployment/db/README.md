# Naming Convention

A clear naming convention helps with orientation and facilitates collaboration within the team.

- Use lower letters when naming database objects.
- For separating words in the database object name, use underscore
- Always go with names in the singular.
- For real-world facts use nouns.
- Names for Indices?

## Tables

tables, columns, primary and foreign keys, stored procedures, functions, views,

## Columns

- id
- uuid
- tstamp (short for timestamp)
- i (short for identity)
- n (short for name)
- 

# Tools

## Linter

We use SQLFluff to check the SQL scripts.

Check a single sql script:

```
sqlfluff lint --dialect sqlite up-1-create-table-migration-status.sql 
All Finished 📜 🎉!
```

Check a whole directory recursively (here with a missing indentation):

```
sqlfluff lint --dialect sqlite .
== [0.1.0/up-1-create-table-migration-status.sql] FAIL                                                                                      
L:   2 | P:   4 | L003 | Expected 1 indentation, found less than 1 [compared to
                       | line 01]
All Finished 📜 🎉!
``` 

# Foreign Key Constraints

We use 

always: ON UPDATE RESTRICT (because Kodiak does not change primary keys!)

with ON DELETE it depends:

ON DELETE RESTRICT:
ON DELETE CASCADE:
ON DELETE SET NULL: for tables where the records should remain => make sure that the foreign 
key column is allowed to be set to null!

# Structure for Migrations

Kodiak uses SQL scripts to migrate the database to the app's version. We defined a directory 
structure and a naming convention for the SQL scripts to make this work.

## Directory structure

Directories follow this convention: db/DBMS/migration/VERSION/DIRECTION/SQL_SCRIPT.

- DBMS: only sqlite is supported
- VERSION: semver version string, app version equals database version
- DIRECTION: either up or down
- SQL_SCRIPT: see below

## SQL Script

SQL scripts follow this convention: SEQ_NUMBER-DESCRIPTION.sql.

- SEQ_NUMBER: positive integer, unique within this directory
- DESCRIPTION: arbitrary description of the script.

Please note: file extension must be .sql.

# Reminder on how to write an SQL script

- A statement can span multiple lines, just insert a line break and continue the statement on the next line.
- All statements are finalized with a ';'
- Leading and trailing whitespace is ignored
- Empty lines are ignored
- Single-line comments start with a '--', such comments can also be at the end of a line.
- Multi-line comments start with a '/*' and end with a '*/'

Example:

```sql
--
-- Namespace is the top-level object in Kodiak's object hierarchy.
--
CREATE TABLE IF NOT EXISTS namespace (
    id INTEGER NOT NULL PRIMARY KEY,
    uuid TEXT NOT NULL UNIQUE,
    n TEXT NOT NULL
) STRICT;
```

# Migrations

tbd, this is taken from https://medium.com/walkin/database-migration-writing-scripts-best-practices-3634c2134782
Add Guards to Scripts: Guard Clauses are a good way of ensuring that Murphy’s law will have no consequences.

Every migration script needs a way to check the preconditions in the environment in which it will run to make sure the script has the right and that it is idempotent, meaning that running it repeatedly will have no further effect. For this purpose, we include in every script a guard clause that will, for example, check to see whether the migration task has already been accomplished before continuing to run it.

IF EXISTS ( SELECT 1 FROM information_schema.Tables WHERE table_schema = 'MySchema' AND TABLE_NAME = 'MyTableName' )
PRINT 'the table exists'
ELSE
PRINT 'The table does not exists'

# DBMS specific definitions

## SQLite

In SQLite, the purpose of AUTOINCREMENT is to prevent the reuse of ROWIDs from previously deleted rows. 
The AUTOINCREMENT keyword imposes extra CPU, memory, disk space, and disk I/O overhead. So, we do not 
use the AUTOINCREMENT, see https://www.sqlite.org/autoinc.html for further details.

We use TEXT to store timestamps formatted as ISO8601 strings ("YYYY-MM-DD HH:MM:SS.SSS").

We create all tables with STRICT.

See [Datatypes In SQLite](https://www.sqlite.org/datatype3.html) for further information. 

# Links

[SQL Naming Conventions](https://www.sqlshack.com/learn-sql-naming-conventions/)

[SQL Fluff: The SQL Linter for humans](https://sqlfluff.com/)

## SQLite

[SQLite Foreign Key](https://www.sqlitetutorial.net/sqlite-foreign-key/)

https://www.sqlite.org/lang_createindex.html

https://www.sqlite.org/foreignkeys.html#fk_indexes

https://www.sqlite.org/partialindex.html

https://www.w3schools.com/SQl/sql_ref_keywords.asp
