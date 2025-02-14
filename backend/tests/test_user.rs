use reqwest::Client;
use serde_json::json;
use tokio;

const BASE_URL: &str = "http://localhost:8080";

#[tokio::test]
async fn test_create_user() {
    let client = Client::new();
    let res = client
        .post(format!("{}/users", BASE_URL))
        .json(&json!({
            "name": "John Doe",
            "email": "john@example.com",
            "password": "securepassword"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);
}

#[tokio::test]
async fn test_get_users() {
    let client = Client::new();
    let res = client
        .get(format!("{}/users", BASE_URL))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn test_update_user() {
    let client = Client::new();
    let res = client
        .put(format!("{}/users/1", BASE_URL))
        .json(&json!({
            "name": "John Updated",
            "email": "john@example.com"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn test_delete_user() {
    let client = Client::new();
    let res = client
        .delete(format!("{}/users/1", BASE_URL))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 204);
}
