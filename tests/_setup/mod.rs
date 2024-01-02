use std::net::TcpListener;

pub fn spawn_app_http() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port.");
    let port = listener.local_addr().unwrap().port();

    let server = kodiak_web_server::run_http(listener).expect("Failed to start server.");
    let _ = tokio::spawn(server);

    format!("http://localhost:{port}")
}

pub fn spawn_app_https() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to random port.");
    let port = listener.local_addr().unwrap().port();

    let server = kodiak_web_server::run_https(listener).expect("Failed to start server.");
    let _ = tokio::spawn(server);

    format!("https://localhost:{port}")
}
