use crate::_setup::spawn_app_http;

use reqwest::redirect::Policy;
use reqwest::StatusCode;

#[tokio::test]
async fn redirect() {
    let address = spawn_app_http();

    let client = reqwest::Client::builder().redirect(Policy::none()).build().unwrap();

    let response = client
        .get(format!("{address}/"))
        .send()
        .await
        .expect("Failed to send request.");

    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
}
