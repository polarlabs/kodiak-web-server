#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

SQLITE_MIGRATIONS="${SCRIPT_DIR}/../../../deployment/db/sqlite"
DATABASE="${SCRIPT_DIR}/../db/_kodiak.sqlite3"

FILES=$(find $SQLITE_MIGRATIONS -type f -name "*.sql" | grep -v "/down/" | sort -V)
for FILE in $FILES; do
  cat $FILE | sqlite3 $DATABASE
  if [ $? -ne 0 ]; then
    echo "Error in $FILE"
  fi
done
