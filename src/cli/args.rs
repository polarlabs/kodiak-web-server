// Internal
use super::log_level::LogLevel;
use crate::constants;
use crate::util::fs;

// External
use clap::{crate_authors, crate_name, crate_version, value_parser};
use clap::{Parser};
use config::ConfigError;

// Std
use std::fmt::{Debug, Display, Formatter};
use std::path::PathBuf;

// Clap creates help text from doc comments (introduced with ///)
#[derive(Parser, Clone, Debug)]
#[command(about, before_help = legal_note(), version = version())]
pub struct Args {
    /// Path to config file
    #[arg(short = 'c', long = "config", env = constants::ENV_KODIAK_WS_CONFIG, default_value = constants::KODIAK_WS_DEFAULT_CONFIG)]
    pub(crate) config: PathBuf,

    /// Level of logs generated
    #[arg(short = 'l', long = "log-level", env = constants::ENV_KODIAK_WS_LOG_LEVEL, default_value = constants::KODIAK_WS_DEFAULT_LOG_LEVEL)]
    log_level: LogLevel,
    
    /// Verbosity allows to increase log level ad hoc (can be specified multiple times)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Interface(s) to bind to. Use 0.0.0.0 to bind to all interfaces
    #[arg(short = 'i', long = "interface", env = constants::ENV_KODIAK_WS_INTERFACE, default_value = constants::KODIAK_WS_DEFAULT_INTERFACE)]
    interface: String,

    /// HTTP port number, used for (1) ACME client and (2) redirect to HTTPS
    #[arg(long = "http-port", value_parser = value_parser!(u16).range(1..=65535), env = constants::ENV_KODIAK_WS_HTTP_PORT, default_value_t = constants::KODIAK_WS_DEFAULT_HTTP_PORT)]
    http_port: u16,

    /// HTTPS port number
    #[arg(long = "https-port", value_parser = value_parser!(u16).range(1..=65535), env = constants::ENV_KODIAK_WS_HTTPS_PORT, default_value_t = constants::KODIAK_WS_DEFAULT_HTTPS_PORT)]
    https_port: u16,
}

fn legal_note() -> String {
    format!(
        "{} ({}). Licensed under {}. {} represented by <{}>.",
        crate_name!(),
        crate_version!(),
        constants::LICENSE,
        constants::COPYRIGHT,
        crate_authors!(", ")
    )
}

fn version() -> &'static str {
    concat!("(", crate_version!(), ").")
}

#[derive(Debug)]
pub enum CliError {
    ConfigNotFound,
    ConfigNotFile,
    ConfigNotReadable,
}

impl Args {
    // Validate args provided by user.
    pub fn validate() -> Result<Args, CliError> {
        let mut args = Args::parse();

        // Check config file.
        let config_file = fs::File::new(&args.config.clone());
        validate_config_file(config_file)?;

        // Adopt log level to verbosity.
        args.log_level = LogLevel::validate(args.log_level.clone(), args.verbosity);
        
        Ok(args)
    }
}

fn validate_config_file(config: fs::File) -> Result<(), CliError> {
    if !config.exists() {
        return Err(CliError::ConfigNotFound);
    }

    if !config.is_file() {
        return Err(CliError::ConfigNotFile);
    }

    if !config.is_readable() {
        return Err(CliError::ConfigNotReadable);
    }

    Ok(())
}

impl Display for CliError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            CliError::ConfigNotFound => "config file not found",
            CliError::ConfigNotFile => "config file must be a file",
            CliError::ConfigNotReadable => "config file not readable",
        };

        write!(f, "An error occurred: {}", message)
    }
}

impl Default for Args {
    fn default() -> Self {
        Args {
            config: PathBuf::from(constants::KODIAK_WS_DEFAULT_CONFIG),
            log_level: LogLevel::default(),
            verbosity: constants::KODIAK_WS_DEFAULT_VERBOSITY,
            interface: String::from(constants::KODIAK_WS_DEFAULT_INTERFACE),
            http_port: constants::KODIAK_WS_DEFAULT_HTTP_PORT,
            https_port: constants::KODIAK_WS_DEFAULT_HTTPS_PORT,
        }
    }
}

// Implementing trait `Source` for `Args` allows to merge
// `Args` in a `Config` (see module config).
// todo: create a test to ensure that Args can be converted to Config
//       => map must be complete!
//       better solution: impl From<Args> for Config as Source is implemented for Config
impl config::Source for Args {
    fn clone_into_box(&self) -> Box<dyn config::Source + Send + Sync> {
        Box::new((*self).clone())
    }

    fn collect(&self) -> Result<config::Map<String, config::Value>, ConfigError> {
        let mut map = config::Map::new();

        map.insert("interface".to_string(), config::Value::from(self.interface.to_string()));
        map.insert("log_level".to_string(), config::Value::from(self.log_level.to_string()));
        map.insert("http_port".to_string(), config::Value::from(self.http_port));
        map.insert("https_port".to_string(), config::Value::from(self.https_port));

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use config::Source;
    use super::*;

    fn init_args() -> Args {
        Args {
            config: PathBuf::from("config/default.toml"),
            log_level: LogLevel::Off,
            verbosity: 1,
            interface: "0.0.0.0".to_string(),
            http_port: 0,
            https_port: 0,
        }
    }

    #[test]
    fn test_source_from_args() {
        let args = init_args();

        let args = args.collect().unwrap();

        for (key, value) in args {
            match key.as_str() {
                "config" => assert_eq!(value.to_string(), "\"config/default.toml\""),
                "log_level" => assert_eq!(value.to_string(), "off"),
                "verbosity" => assert_eq!(value.to_string(), "1"),
                _ => {}
            }
        }
    }
}
