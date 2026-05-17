use crate::db::schema::{Schema, SchemaPK};
use sqlx::SqlitePool;

pub(crate) async fn insert(pool: &SqlitePool, schema: Schema) -> Result<(), sqlx::Error> {
    let result = sqlx::query!(
        r#"INSERT INTO schema
                       (uuid, name, ts_created)
                VALUES ($1,   $2, $3);"#,
        schema.uuid,
        schema.name,
        schema.ts_created
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub(crate) async fn select_one(pool: &SqlitePool, schema: SchemaPK) -> Result<Schema, sqlx::Error> {
    let schema = sqlx::query_as!(
        Schema,
        r#"SELECT id,
                  uuid,
                  name,
                  ts_created,
                  ts_updated
             FROM schema
            WHERE id = $1;"#,
        schema
    )
    .fetch_one(pool)
    .await?;

    Ok(schema)
}

pub(crate) async fn select_one_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<Schema>, sqlx::Error> {
    let schema = sqlx::query_as!(
        Schema,
        r#"SELECT id,
                  uuid,
                  name,
                  ts_created,
                  ts_updated
             FROM schema
            WHERE name = $1;"#,
        name
    )
    .fetch_optional(pool)
    .await?;

    Ok(schema)
}

// Looks up a Schema by UUID and returns its id (primary key), fails if not found.
pub(crate) async fn select_one_id(pool: &SqlitePool, uuid: &str) -> Result<SchemaPK, sqlx::Error> {
    let record = sqlx::query!(
        r#"SELECT id
             FROM schema
            WHERE uuid = $1;"#,
        uuid
    )
    .fetch_one(pool)
    .await?;

    Ok(SchemaPK(record.id))
}
