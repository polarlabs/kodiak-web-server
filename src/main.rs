use kodiak_web_server::{init, run_https, run_http};

use std::net::TcpListener;

const INTERFACE: &str = "0.0.0.0"; // Binds to all interfaces.
const HTTP_PORT: u16 = 8080;
const HTTPS_PORT: u16 = 8443;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Initialize runtime
    let listener = TcpListener::bind(format!("{INTERFACE}:{HTTP_PORT}")).expect("Failed to bind to port {HTTP_PORT}.");
    init(listener).await;

    // Start HTTPS first to ensure redirect from HTTP works
    let listener = TcpListener::bind(format!("{INTERFACE}:{HTTPS_PORT}")).expect("Failed to bind to port {HTTPS_PORT}.");
    let https_server = run_https(listener).expect("Failed to start http server.");
    tokio::spawn(https_server);

    let listener = TcpListener::bind(format!("{INTERFACE}:{HTTP_PORT}")).expect("Failed to bind to port {HTTP_PORT}.");
    run_http(listener)?.await
}
