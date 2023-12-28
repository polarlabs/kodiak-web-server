use kodiak_web_server::{run_https, run_http};

use std::net::TcpListener;

const INTERFACE: &str = "0.0.0.0"; // Binds to all interfaces.
const HTTP_PORT: u16 = 8080;
const HTTPS_PORT: u16 = 8443;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("{INTERFACE}:{HTTP_PORT}")).expect("Failed to bind to random port.");
    let http_server = run_http(listener).expect("Failed to start http server.");
    let _ = tokio::spawn(http_server);

    let listener = TcpListener::bind(format!("{INTERFACE}:{HTTPS_PORT}")).expect("Failed to bind to random port.");
    run_https(listener)?.await
}
