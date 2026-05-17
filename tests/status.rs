use crate::_setup::spawn_app_https;

#[tokio::test]
async fn get_status() {
    let address = spawn_app_https().await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client
        .get(format!("{address}/status"))
        .send()
        .await
        .expect("Failed to send request.");

    assert!(response.status().is_success());
    assert_eq!(response.content_length(), Some(0));

    let x_robots_tag = response
        .headers()
        .get("X-Robots-Tag")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(x_robots_tag, "noindex");
}

#[tokio::test]
async fn wstg_info_01_status_has_header_robots_noindex() {
    let address = spawn_app_https().await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client
        .get(format!("{address}/status"))
        .send()
        .await
        .expect("Failed to send request.");

    let x_robots_tag = response
        .headers()
        .get("X-Robots-Tag")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(x_robots_tag, "noindex");
}
