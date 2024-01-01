use kodiak_web_server::{run_https, run_http, cert_remaining_validity, gen_tls_cert};

use std::net::TcpListener;

const INTERFACE: &str = "0.0.0.0"; // Binds to all interfaces.
const HTTP_PORT: u16 = 8080;
const HTTPS_PORT: u16 = 8443;

const CERT_VALIDITY_THRESHOLD: u32 = 45;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    if cert_remaining_validity() < CERT_VALIDITY_THRESHOLD {
        let listener = TcpListener::bind(format!("{INTERFACE}:{HTTP_PORT}")).expect("Failed to bind to port {HTTP_PORT}.");
        match gen_tls_cert(listener, "kodiak.polarlabs.io", "contact@polarlabs.io").await {
            Ok(cert) => {
                println!("Success: got a cert ({:#?})", cert);
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }

    // Start HTTPS first to ensure redirect from HTTP works
    let listener = TcpListener::bind(format!("{INTERFACE}:{HTTPS_PORT}")).expect("Failed to bind to port {HTTPS_PORT}.");
    let https_server = run_https(listener).expect("Failed to start http server.");
    tokio::spawn(https_server);

    let listener = TcpListener::bind(format!("{INTERFACE}:{HTTP_PORT}")).expect("Failed to bind to port {HTTP_PORT}.");
    run_http(listener)?.await
}
