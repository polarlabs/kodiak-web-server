mod logger;

// Internal
use kodiak_web_server::{cli, constants, init, pool, run_http, run_https, Config};
use kodiak_web_server::cli::{Args, CliError};
use kodiak_web_server::constants::{KODIAK_WS_DEFAULT_HTTPS_PORT, KODIAK_WS_DEFAULT_HTTP_PORT, KODIAK_WS_DEFAULT_INTERFACE};
use kodiak_web_server::net::TcpListener as OwnTcpListener;

// External
#[cfg(feature = "dev-profile")]
use dotenv::dotenv;

// Std
use std::net::TcpListener;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let args = match startup() {
        Ok(args) => args,
        Err(e) => return e,
    };

    let config = Config::new(args);
    
    // todo: next read config to get log config to be able to initialize the logger.
    // todo merge args into config: Config

    // todo: initialize logger with Args / Config, even if cli:Args::validate / config:Config::validate went wrong. e.g. missing config file.
    // success case: initialize logger using log-level from args / config.
    // failure case: initialize logger so that the failed cli parsing / config parsing gets logged, log failures occurred so far, set logger to log-level from args / config.
    // idea to get this done: set an independent log level for module cli and module config and then call into Args / Config to get the events logged.
        
    match config {
        Ok(config) => {
            // Next we have to set up the logging!
            // Only supply the necessary arguments to logger.
            logger::init_logger(&config);
            
            log::info!("Config: {:?}", config);

            let pool = pool().await;

            // Initialize runtime
            let listener = OwnTcpListener::bind(KODIAK_WS_DEFAULT_INTERFACE, KODIAK_WS_DEFAULT_HTTP_PORT);
            init(listener.0, config.clone()).await;

            // Start HTTPS first to ensure redirect from HTTP works
            let listener = TcpListener::bind(format!("{KODIAK_WS_DEFAULT_INTERFACE}:{KODIAK_WS_DEFAULT_HTTPS_PORT}"))
                .expect("Failed to bind to port {HTTPS_PORT}.");
            let https_server =
                run_https(listener, pool).expect("Failed to start http server.");
            tokio::spawn(https_server);

            let listener = TcpListener::bind(format!("{KODIAK_WS_DEFAULT_INTERFACE}:{KODIAK_WS_DEFAULT_HTTP_PORT}"))
                .expect("Failed to bind to port {HTTP_PORT}.");
            run_http(listener).unwrap().await;

            ExitCode::SUCCESS
        }
        Err(e) => {
            // todo: a ConfigError might not be fatal! Use Custom Error Type here.
            log::error!("Config error: {}", e);
            ExitCode::from(constants::EC_CONFIG_ERROR)
        }
    }
}

fn startup() -> Result<cli::Args, ExitCode> {
    // Load environment variables from ".env" file, during development and testing.
    #[cfg(feature = "dev-profile")]
    dotenv().ok();

    // Parse CLI Arguments first, even before initializing logging.
    // Errors are handled within cli::Args.
    match cli::Args::validate() {
        Ok(args) => Ok(args),
        Err(e) => {
            match e {
                CliError::ConfigNotFound => Err(ExitCode::from(constants::EC_CLIERROR_CONFIG_NOT_FOUND)),
                CliError::ConfigNotFile => Err(ExitCode::from(constants::EC_CLIERROR_CONFIG_NOT_FILE)),
                CliError::ConfigNotReadable => Err(ExitCode::from(constants::EC_CLIERROR_CONFIG_NOT_READABLE)),
            }
        }
    }
}
