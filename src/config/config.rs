// Internal
use super::Database;
use crate::cli::Args;
use crate::cli::LogLevel;

// External
use config::{Config as Configuration, ConfigError, File};
use serde::Deserialize;

// Std
// no use statements for Std yet

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    log_level: LogLevel,
    interface: String,
    http_port: u16,
    https_port: u16,
    database: Database, 
}

impl Config {
    pub fn new(args: Args) -> Result<Self, ConfigError> {
        let s = Configuration::builder()
            // Start off by merging in the "default" configuration file
            .add_source(File::from(args.config.clone()))
            .add_source(args)
            .build()?;

        log::debug!("Configuration: {:?}", s);

        // You can deserialize (and thus freeze) the entire configuration as
        s.try_deserialize()
    }
    
    pub fn log_level(&self) -> LogLevel {
        self.log_level.clone()
    }
}
