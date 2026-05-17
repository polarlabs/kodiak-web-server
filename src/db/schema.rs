use crate::db::timestamp::Timestamp;
use crate::db::timestamp_option::TimestampOption;
use crate::db::{sqlite, Pool};
use crate::model;
use chrono::{DateTime, SecondsFormat, Utc};
use std::io::Error;
use std::path::Path;

///
/// `db::schema::Schema` represents a Schema record in the database but
/// still abstracting from the various database backends supported by `sqlx`.
///
#[derive(Debug)]
pub(crate) struct Schema {
    pub id: SchemaPK,
    pub uuid: SchemaUuid,
    pub name: String,
    pub ts_created: Timestamp,
    pub ts_updated: TimestampOption,
}

#[derive(sqlx::Type, Copy, Clone, Debug)]
#[sqlx(transparent)]
pub(crate) struct SchemaPK(pub i64);

#[derive(sqlx::Type, Debug)]
#[sqlx(transparent)]
pub(crate) struct SchemaUuid(pub String);

impl From<i64> for SchemaPK {
    fn from(value: i64) -> Self {
        SchemaPK(value)
    }
}

impl From<String> for SchemaUuid {
    fn from(value: String) -> Self {
        SchemaUuid(value)
    }
}

// Insert a Schema.
pub async fn insert(pool: &Pool, schema: Schema) -> Result<(), sqlx::Error> {
    log::info!("Insert schema {:?}", schema);

    let schema = match pool {
        Pool::SqlitePool(pool) => sqlite::schema::insert(pool, schema).await?,
        Pool::PgPool(_) => unimplemented!(),
    };

    Ok(())
}

// Selects a Schema by `Name`.
pub async fn select_one_by_name(pool: &Pool, name: &str) -> Result<Option<Schema>, sqlx::Error> {
    log::info!("Select schema {:?}", name);

    let schema = match pool {
        Pool::SqlitePool(pool) => sqlite::schema::select_one_by_name(pool, name).await?,
        Pool::PgPool(_) => unimplemented!(),
    };

    Ok(schema)
}

impl SchemaPK {
    pub(crate) async fn select_one(pool: &Pool, uuid: &SchemaUuid) -> Result<Self, sqlx::Error> {
        match pool {
            Pool::SqlitePool(pool) => sqlite::schema::select_one_id(pool, &uuid.0).await,
            Pool::PgPool(_) => unimplemented!(),
        }
    }
}

struct Schemas(Vec<Schema>);

impl Schemas {
    // Uses the provided path to create a list of schemas.
    // Schema _kodiak must exist, if not error.
    pub fn from_path<P: AsRef<Path>>(directory: P) -> Result<Self, Error> {
        let schemas = Vec::new();

        // Check if directory exists.

        // Check if directory is writable.

        // Enumerate all files in the directory matching *.sqlite3

        // Check if there is a fs _kodiak.sqlite3.

        // Check if it is writable.

        // Add as first element to Schemas.

        // Iterate over all other files *.sqlite3 and check if they are writeable.
        // Add as element to Schemas.

        Ok(Schemas(schemas))
    }
}
