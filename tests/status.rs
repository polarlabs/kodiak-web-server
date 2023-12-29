use crate::_setup::spawn_app_https;

#[tokio::test]
async fn get_status() {
    let address = spawn_app_https();

    //let client = reqwest::Client::new();
    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();

    let response = client
        .get(format!("{address}/status"))
        .send()
        .await
        .expect("Failed to send request.");

    assert!(response.status().is_success());
    assert_eq!(response.content_length(), Some(0));
}
