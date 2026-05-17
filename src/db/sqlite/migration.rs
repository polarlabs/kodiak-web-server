use chrono::{DateTime, Utc};
use crate::db::migration::{Migrations, Migration, Script, Scripts};
use crate::db::migration::{Resolution, Status};

use rust_decimal::{Decimal, prelude::FromPrimitive};
use semver::Version as SemVer;
use sqlx::{Error, SqlitePool};

/// Executes `migrations` and their `scripts` up to app_version.
///
/// Features:
/// - allows to report progress based on table migration_status
///
/// Input:
/// `pool`: database connection pool
/// `migrations`: list of migrations with two properties:
///  - sorted in ascending order, i.e. from lower to higher version.
///  - first migration in the list is the successor to the current db version.
/// `v_target`: target version
///
/// Steps:
/// 1. iterate over migrations and filter for `Direction::Up` and `Version`.
/// 2. iterate over migration.scripts
///    - insert script into migration_status
/// => all scripts to be run have been inserted into migration_status.
/// Note: table has a UNIQUE constraint ensuring that a script is only inserted once.
///
/// 3. select all outstanding scripts and deserialize
/// 4. iterate over migration.scripts
///    - update script as `Status::Running`
///    - execute script:
///      - Ok: update script with `Status::Done` and `Resolution::Succeeded`
///      - Err: update script with `Status::Done` and `Resolution::Failed`
///    - update migration_history:
///      - migration's final script: copy record from status to history
///      - any other script: insert record into history and delete it from status
///
/// Error handling: all errors are handled by this function locally.
/// - when a migration script fails, the migration is aborted.
///
/// todo: an aborted migration hinders the start of the application
///
pub(crate) async fn execute_up_to(pool: &SqlitePool, migrations: &Migrations, v_target: SemVer) {
    let fn_name = "execute_up_to";
    let mut fatal_error: Option<Error> = None;

    log::trace!("{}: {} migrations to check", fn_name, migrations.all().len());

    // Insert all migration scripts.
    for migration in migrations.all() {
        if migration.direction() == crate::db::migration::Direction::Up &&
            migration.version() <= v_target {
            let scripts = migration.scripts().all();
            for script in scripts {
                match insert_status(pool, migration, script).await {
                    Err(e) => log::error!("{}: insert script {} failed  with {} .", fn_name, script.filename(), e),
                    Ok(_) => log::debug!("{}: insert script {} succeeded .", fn_name, script.filename())
                }
            }
        }
    }

    // Execute all migration scripts
    for migration in migrations.all() {
        if migration.direction() == crate::db::migration::Direction::Up &&
            migration.version() <= v_target {
            match select_status(pool, migration).await {
                Err(e) => log::error!("{}: select migration's {} scripts failed with {} .", fn_name, migration, e),
                Ok(scripts) => {
                    for (i, script) in scripts.iter().enumerate() {
                        let mut script = script.clone();
                        script.update(Status::Running, None);

                        match update_status(pool, id, &script).await {
                            Ok(_) => log::debug!("{}: update script {} succeeded .", fn_name, script.filename()),
                            Err(e) => log::error!("{}: update script {} failed  with {} .", fn_name, script.filename(), e)
                        }

                        match execute(pool, migration, &script).await {
                            Ok(_) => {
                                script.update(Status::Done, Some(Resolution::Succeeded));

                                match update_status(pool, id, &script).await {
                                    Ok(_) => log::debug!("{}: update script {} succeeded .", fn_name, script.filename()),
                                    Err(e) => log::error!("{}: update script {} failed  with {} .", fn_name, script.filename(), e)
                                }
                            }
                            Err(e) => {
                                log::error!("{}: script {} failed with {} .", fn_name, script.filename(), e);
                                fatal_error = Some(e);

                                script.update(Status::Done, Some(Resolution::Failed));
                                match update_status(pool, id, &mut script).await {
                                    Ok(_) => log::debug!("{}: update script {} succeeded .", fn_name, script.filename()),
                                    Err(e) => log::error!("{}: update script {} failed  with {} .", fn_name, script.filename(), e)
                                }
                            }
                        }

                        if ( i + 1 ) < migration.scripts().all().len() {
                            // Move record from status to history.
                            insert_history(pool, migration, &script).await?;
                            delete_status(pool, id).await?;
                        } else {
                            // Copy record to history.
                            insert_history(pool, migration, &script).await?;
                        }

                        // todo: migration has to terminate when a script fails
                        //log::error!("{}: terminating migration {} .", fn_name, migration);
                        //return Err(e);
                    }
                }
            }
        }
    }
}

pub async fn execute(pool: &SqlitePool, migration: &Migration, script: &Script) -> Result<(), Error> {
    let fn_name = "execute";

    let path = format!("deployment/db/{}/migration/{}/{}/{}", migration.driver(), migration.version(), migration.direction(), script.filename());
    log::info!("{}: execute script: {}", fn_name, path);

    let sql_query = std::fs::read_to_string(path)?;

    let result = sqlx::query(&sql_query)
        .execute(pool)
        .await?;

    Ok(())
}

pub async fn select_status(pool: &SqlitePool, migration: &Migration) -> Result<Vec<Script>, Error> {
    let fn_name = "select_status";
    let version = migration.version().to_string();
    let direction = migration.direction().to_string();

    let scripts = sqlx::query_as!(
        Script,
        r#"SELECT rank, filename, hash, status, resolution, tstamp AS timestamp
             FROM migration_status
            WHERE v = ?
              AND direction = ?
         ORDER BY rank ASC;
        "#,
        version,
        direction
    )
        .fetch_all(pool)
        .await?;

    Ok(scripts)
}

pub async fn insert_status(pool: &SqlitePool, migration: &Migration, script: &Script) -> Result<i64, Error> {
    let fn_name = "insert_status";

    log::debug!("{}: migration: {}/{}/{} .", fn_name, migration.driver(), migration.version(), migration.direction());
    log::debug!("{}: script: {} .", fn_name, script.filename());
    log::trace!("{}: migration: {:?} .", fn_name, migration);
    log::trace!("{}: script: {:?} .", fn_name, script);

    let driver = migration.driver().to_str();
    let version = migration.version().to_string();
    let direction = migration.direction().to_str();
    let rank = script.rank();
    let filename = script.filename();
    let hash = script.hash();
    let status = script.status().to_str();
    let resolution = script.resolution().map(|r| r.to_str().to_owned());
    let mut progress = Decimal::from_f32(script.rank() as f32 / migration.scripts().all().len() as f32).unwrap();
    progress.rescale(5);
    let progress = progress.to_string();
    let timestamp = script.timestamp();

    let record = sqlx::query!(
            r#"INSERT INTO migration_status
                           (driver, v, direction, rank, filename, hash, status, resolution, progress, tstamp)
                    VALUES (?,      ?, ?,         ?,    ?,        ?,    ?,      ?,          ?,        ?)
                 RETURNING *;
            "#,
            driver,
            version,
            direction,
            rank,
            filename,
            hash,
            status,
            resolution,
            progress,
            timestamp
        )
        .fetch_one(pool)
        .await?;

    log::trace!("{}: record: {:?} .", fn_name, record);

    Ok(record.id)
}

pub async fn update_status(pool: &SqlitePool, row_id: i64, script: &Script) -> Result<(), Error> {
    let fn_name = "update_status";

    log::debug!("{}: row_id: {}, script: {} .", fn_name, row_id, script.filename());
    log::trace!("{}: row_id: {}, script: {:?} .", fn_name, row_id, script);

    let status = script.status().to_str();
    let resolution = script.resolution().map(|r| r.to_str().to_owned());
    let timestamp = script.timestamp();

    let result = sqlx::query!(
        r#"UPDATE migration_status
              SET status = ?,
                  resolution = ?,
                  tstamp = ?
            WHERE id = ?;
        "#,
        status,
        resolution,
        timestamp,
        row_id
    )
        .execute(pool)
        .await?;

    log::trace!("{}: result: {:?} .", fn_name, result);

    Ok(())
}

pub async fn delete_status(pool: &SqlitePool, row_id: i64) -> Result<(), Error> {
    let fn_name = "delete_status";

    log::debug!("{}: row_id: {} .", fn_name, row_id);

    let result = sqlx::query!(
        r#"DELETE FROM migration_status
                 WHERE id = ?;
        "#,
        row_id
    )
        .execute(pool)
        .await?;

    log::trace!("{}: result: {:?} .", fn_name, result);

    Ok(())
}

pub async fn insert_history(pool: &SqlitePool, migration: &Migration, script: &Script) -> Result<i64, Error> {
    let fn_name = "insert_history";

    log::debug!("{}: migration: {}/{}/{} .", fn_name, migration.driver(), migration.version(), migration.direction());
    log::debug!("{}: script: {} .", fn_name, script.filename());
    log::trace!("{}: migration: {:?} .", fn_name, migration);
    log::trace!("{}: script: {:?} .", fn_name, script);

    let driver = migration.driver().to_str();
    let version = migration.version().to_string();
    let direction = migration.direction().to_str();
    let rank = script.rank();
    let filename = script.filename();
    let hash = script.hash();
    let status = script.status().to_str();
    let resolution = script.resolution().map(|r| r.to_str().to_owned());
    let timestamp = script.timestamp();

    let record = sqlx::query!(
            r#"INSERT INTO migration_history
                           (driver, v, direction, rank, filename, hash, status, resolution, tstamp)
                    VALUES (?,      ?, ?,         ?,    ?,        ?,    ?,      ?,          ?)
                 RETURNING *;
            "#,
            driver,
            version,
            direction,
            rank,
            filename,
            hash,
            status,
            resolution,
            timestamp
        )
        .fetch_one(pool)
        .await?;

    log::trace!("{}: record: {:?} .", fn_name, record);

    Ok(record.id)
}
