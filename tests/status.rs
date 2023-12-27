use crate::_setup::spawn_app;

#[tokio::test]
async fn get_status() {
    spawn_app();

    let client = reqwest::Client::new();

    let response = client
        .get("http://localhost:8080/status")
        .send()
        .await
        .expect("Failed to send request.");

    assert!(response.status().is_success());
    assert_eq!(response.content_length(), Some(0));
}
