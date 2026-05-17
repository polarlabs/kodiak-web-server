pub struct TcpListener(pub std::net::TcpListener);

impl TcpListener {
    pub fn bind(interface: &str, port: u16) -> Self {
        let tcp_listener = std::net::TcpListener::bind(format!("{interface}:{port}"))
            .expect("Failed to bind to port {HTTP_PORT}.");

        TcpListener(tcp_listener)
    }
}
