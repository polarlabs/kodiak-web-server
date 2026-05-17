// Internal
// no internal use statements yet

use std::fmt::{Display, Formatter};
// External
use clap::ValueEnum;
use log::LevelFilter;
use serde::{Deserialize, Deserializer, Serialize};
use crate::constants;

// Std
// no use statements for Std yet

// LogLevel uses explicit discriminators to match Verbosity easily.
#[derive(Deserialize, ValueEnum, PartialEq, Clone, Debug)]
pub enum LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl LogLevel {
    // Align LogLevel with Verbosity, if Verbosity is higher
    pub fn validate(log_level: LogLevel, verbosity: u8) -> LogLevel {
        let mut log_level = log_level;
        // A Verbosity of 0 corresponds to LogLevel::Info (3)
        let verbosity_normalized = verbosity + 3;

        if (verbosity_normalized) > (log_level.clone() as u8) {
            log_level = LogLevel::from(verbosity_normalized);
        }

        log_level
    }
}

impl Default for LogLevel {
    fn default() -> Self {
        LogLevel::from(constants::KODIAK_WS_DEFAULT_LOG_LEVEL)
    }
}

impl Display for LogLevel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let log_level = match self {
            LogLevel::Off => "off",
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        };

        write!(f, "{}", log_level)
    }
}

impl From<&str> for LogLevel {
    fn from(value: &str) -> Self {
        match value {
            "off" => LogLevel::Off,
            "error" => LogLevel::Error,
            "warn" => LogLevel::Warn,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Trace,
        }
    }
}

impl From<u8> for LogLevel {
    fn from(value: u8) -> Self {
        match value {
            x if x == LogLevel::Off as u8 => LogLevel::Off,
            x if x == LogLevel::Error as u8 => LogLevel::Error,
            x if x == LogLevel::Warn as u8 => LogLevel::Warn,
            x if x == LogLevel::Info as u8 => LogLevel::Info,
            x if x == LogLevel::Debug as u8 => LogLevel::Debug,
            x if x == LogLevel::Trace as u8 => LogLevel::Trace,
            _ => LogLevel::Trace,
        }
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_log_level_warn_vs_verbosity_3() {
        let log_level = LogLevel::Warn;
        let verbosity:u8 = 3 ;
        
        let log_level = LogLevel::validate(log_level, verbosity);

        assert_eq!(log_level, LogLevel::Trace);
    }

    #[test]
    fn test_validate_log_level_warn_vs_verbosity_0() {
        let log_level = LogLevel::Warn;
        let verbosity:u8 = 0;

        let log_level = LogLevel::validate(log_level, verbosity);

        assert_eq!(log_level, LogLevel::Info);
    }

    #[test]
    fn test_validate_log_level_info_vs_verbosity_2() {
        let log_level = LogLevel::Info;
        let verbosity:u8 = 2;

        let log_level = LogLevel::validate(log_level, verbosity);

        assert_eq!(log_level, LogLevel::Trace);
    }

    #[test]
    fn test_validate_log_level_error_vs_verbosity_5() {
        let log_level = LogLevel::Error;
        let verbosity:u8 = 5;

        let log_level = LogLevel::validate(log_level, verbosity);

        assert_eq!(log_level, LogLevel::Trace);
    }
}
