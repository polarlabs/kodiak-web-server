use crate::constants;
use crate::db::sqlite;
use crate::fs;

use semver::Version as SemVer;
use sqlx::{PgPool, SqlitePool};

#[derive(Clone)]
pub enum Pool {
    SqlitePool(SqlitePool),
    PgPool(PgPool),
}

pub async fn pool(url: &str, app_version: SemVer) -> Option<Pool> {
    if url.contains("://") {
        let (scheme, db_path) = url.split_once("://").unwrap();

        match scheme {
            "sqlite" | "fs" => {
                fs::create_parent_dirs(db_path);

                let pool = sqlite::startup(db_path, app_version).await;
                match pool {
                    Ok(pool) => Some(Pool::SqlitePool(pool)),
                    Err(e) => {
                        log::error!("Failed to connect to database {} with {}.", url, e);
                        None
                    }
                }
            }
            unsupported_scheme => {
                log::error!("Unsupported scheme {} in database uri.", unsupported_scheme);
                None
            }
        }
    } else {
        log::error!("Malformed database uri {}, use scheme://path.", url);
        None
    }
}
