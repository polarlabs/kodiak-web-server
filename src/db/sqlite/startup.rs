use std::path::Path;

use semver::Version as SemVer;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous};
use sqlx::Error;
use sqlx::SqlitePool;

use crate::constants;
// todo uncomment
//use crate::db::migration::Migrations;

pub async fn startup<P: AsRef<Path>>(
    filename: P,
    app_version: SemVer,
) -> Result<SqlitePool, Error> {
    let pool = connect(filename).await?;

    println!("App Version: {:#?}", app_version);
    let db_version = db_version(&pool).await?;
    println!("DB Version: {:#?}", db_version);

    migrate(&pool, app_version, db_version).await;

    Ok(pool)
}

async fn connect<P: AsRef<Path>>(filename: P) -> Result<SqlitePool, Error> {
    let options = SqliteConnectOptions::new()
        .filename(filename)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .locking_mode(SqliteLockingMode::Normal)
        .synchronous(SqliteSynchronous::Normal)
        .optimize_on_close(true, None);

    SqlitePool::connect_with(options).await
}

async fn db_version(pool: &SqlitePool) -> Result<Option<SemVer>, Error> {
    let migration_status_exists = sqlx::query!(
        r#"SELECT name
             FROM sqlite_master
            WHERE type = 'table'
              AND name = ?;"#,
        "migration_status"
    )
    .fetch_optional(pool)
    .await?;

    match migration_status_exists {
        None => Ok(None),
        Some(_) => {
            let latest_migration_status = sqlx::query!(
                r#"SELECT v
                     FROM migration_status
                    WHERE resolution = ?
                      AND progress = ?
                 ORDER BY tstamp DESC;"#,
                "succeeded",
                1.0
            )
            .fetch_optional(pool)
            .await?;

            match latest_migration_status {
                None => Ok(None),
                Some(latest_migration_status) => {
                    Ok(Some(SemVer::parse(&latest_migration_status.v).unwrap()))
                }
            }
        }
    }
}

async fn migrate(pool: &SqlitePool, app_version: SemVer, db_version: Option<SemVer>) {
    match db_version {
        None => {
            log::info!("migrate: DB version is 'None', run all 'UP' migrations with version <= app_version.");

            // todo uncomment
            /*
            match Migrations::from_path(constants::MIGRATION_DIR) {
                Ok(migrations) => {
                    super::migration::execute_up_to(pool, &migrations, app_version).await;
                }
                Err(e) => {
                    log::error!("Could not read migrations, {e}.")
                }
            }
            */
        }
        Some(db_version) => {
            if app_version > db_version {
                println!(
                    "Run all UP migrations with version > db_version AND version <= app_version."
                );
            } else if app_version < db_version {
                println!(
                    "Run all DOWN migrations with version <= db_version AND version > app_version."
                );
            } else {
                println!("Run no migrations.");
            }
        }
    }
}
