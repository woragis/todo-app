use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::OnceLock;
use tokio;

const BASE_URL: &str = "http://localhost:8080";

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Todo {
    id: String,
    title: String,
    description: String,
    completed: bool,
}

static TODO: OnceLock<Todo> = OnceLock::new();

/// Creates a new todo and saves it globally

#[tokio::test]
async fn test_create_todo() {
    let client = Client::new();
    let res = client
        .post(&format!("{}/todos", BASE_URL))
        .json(&json!({
            "title": "Comprar leite",
            "description": "Ir ao mercado comprar leite",
            "completed": false
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201);
}

#[tokio::test]
async fn test_get_todos() {
    let client = Client::new();
    let res = client
        .get(format!("{}/todos", BASE_URL))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

// #[tokio::test]
// async fn test_create_todo() {
//     let client = Client::new();
//     let res = client
//         .post(&format!("{}/todos", BASE_URL))
//         .json(&json!({
//             "title": "Comprar leite",
//             "description": "Ir ao mercado comprar leite",
//             "completed": false
//         }))
//         .send()
//         .await
//         .unwrap();

//     assert_eq!(res.status(), 201);

//     let todo: Todo = res.json().await.unwrap();
//     TODO.set(todo.clone()).ok(); // Store the whole todo object
//     todo
// }

// #[tokio::test]
// async fn test_get_todos() {
//     let client = Client::new();
//     let res = client
//         .get(format!("{}/todos", BASE_URL))
//         .send()
//         .await
//         .expect("msg");

//     assert_eq!(res.status(), 200);
// }

#[tokio::test]
async fn test_update_todo() {
    let todo = TODO.get().expect("Todo not found"); // Retrieve the full Todo model

    let client = Client::new();
    let res = client
        .put(format!("{}/todos/{}", BASE_URL, todo.id))
        .json(&json!({
            "title": "Comprar pão",
            "description": "Ir à padaria",
            "completed": true
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}

#[tokio::test]
async fn test_delete_todo() {
    let todo = TODO.get().expect("Todo not found");

    let client = Client::new();
    let res = client
        .delete(format!("{}/todos/{}", BASE_URL, todo.id))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
}
