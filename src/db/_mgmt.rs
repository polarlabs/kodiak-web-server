use crate::db;
use crate::db::{sqlite, Pool, Schema};

pub(crate) async fn create_schema(pool: &Pool, schema: Schema) -> Result<(), sqlx::Error> {
    log::info!("Create schema {:?}", schema.name);

    match pool {
        Pool::SqlitePool(pool) => {
            sqlite::create_schema(pool, &schema).await?;
        }
        Pool::PgPool(_) => unimplemented!(),
    };

    db::schema::insert(pool, schema).await?;

    Ok(())
}
