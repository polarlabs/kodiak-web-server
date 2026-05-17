use crate::_setup::spawn_app_https;

#[tokio::test]
async fn wstg_info_01_robots_txt() {
    let address = spawn_app_https().await;
    let robots_txt = "User-agent: *\nDisallow: /\n";

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let response = client
        .get(format!("{address}/robots.txt"))
        .send()
        .await
        .expect("Failed to send request.");

    assert!(response.status().is_success());
    assert_eq!(response.content_length(), Some(robots_txt.len() as u64));

    let content = response.text().await.unwrap();
    assert_eq!(content.len(), robots_txt.len());
    assert_eq!(content.as_str(), robots_txt);
}
