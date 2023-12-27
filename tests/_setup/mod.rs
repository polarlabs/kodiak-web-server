pub fn spawn_app() {
    let server = kodiak_web_server::run().expect("Failed to start server");
    let _ = tokio::spawn(server);
}
