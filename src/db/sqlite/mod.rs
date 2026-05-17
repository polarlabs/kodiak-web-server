// Module wrapping the SQLite backend.

// Module _mgmt provides functions to manage the database, e.g. create a schema.
mod _mgmt;
pub(in crate::db) use _mgmt::create_schema;

pub(crate) mod schema;
mod startup;

// todo uncomment
//pub mod migration;

pub use startup::startup;
