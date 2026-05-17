// Globals, used internally only, not exposed to user or interface.
pub const MIGRATION_DIR: &str = "deployment/db/sqlite/migration";
pub const COPYRIGHT: &str = "Copyright © 2023-2024 Polarlabs";
pub const LICENSE: &str = "AGPL-3.0-only";

// Default values, eventually overwritten by CLI Arguments or environment variables.
pub const KODIAK_WS_DEFAULT_CONFIG: &str = "config/default.toml";
pub const KODIAK_WS_DEFAULT_LOG_LEVEL: &str = "info";
pub const KODIAK_WS_DEFAULT_INTERFACE: &str = "0.0.0.0";
pub const KODIAK_WS_DEFAULT_HTTP_PORT: u16 = 8080;
pub const KODIAK_WS_DEFAULT_HTTPS_PORT: u16 = 8443;
pub const KODIAK_WS_DEFAULT_RUN_MODE: &str = "production";
pub const KODIAK_WS_DEFAULT_VERBOSITY: u8 = 0;

// Names of environment variables.
pub const ENV_KODIAK_WS_CONFIG: &str = "KODIAK_WS_CONFIG";
pub const ENV_KODIAK_WS_LOG_LEVEL: &str = "KODIAK_WS_LOG_LEVEL";
pub const ENV_KODIAK_WS_INTERFACE: &str = "KODIAK_WS_INTERFACE";
pub const ENV_KODIAK_WS_HTTP_PORT: &str = "KODIAK_WS_HTTP_PORT";
pub const ENV_KODIAK_WS_HTTPS_PORT: &str = "KODIAK_WS_HTTPS_PORT";
pub const ENV_KODIAK_WS_RUN_MODE: &str = "KODIAK_WS_RUN_MODE";

// Prefix of environment variables.
pub const KODIAK_WS_ENV_PREFIX: &str = "KODIAK_WS";

// Exit codes
pub const EC_CLIERROR_CONFIG_NOT_FOUND: u8 = 9;
pub const EC_CLIERROR_CONFIG_NOT_FILE: u8 = 10;
pub const EC_CLIERROR_CONFIG_NOT_READABLE: u8 = 11;
pub const EC_CONFIG_ERROR: u8 = 12;
