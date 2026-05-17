use crate::db::Schema;

use sqlx::SqlitePool;

pub(crate) async fn create_schema(pool: &SqlitePool, schema: &Schema) -> Result<(), sqlx::Error> {
    log::info!("Insert schema {:?}", schema);

    // Attach the additional database
    let q = match sqlx::query("ATTACH DATABASE $1 || '.sqlite3' AS $1")
        .bind(&schema.name)
        .execute(pool)
        .await
    {
        Ok(e) => e,
        Err(e) => panic!("FAIL: {:?}", e),
    };

    Ok(())
}
