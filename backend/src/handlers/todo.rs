use std::sync::Arc;

use crate::models::todo::{CreateTodo, Todo};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "todos";
static FIELDS: &str = "title, description, completed";
static UPDATE_FIELDS: &str = "title = $1, description = $2, completed = $3";
static FIELDS_INPUT: &str = "$1, $2, $3";

/// **Create User**
pub async fn create_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<CreateTodo>,
) -> Result<StatusCode, StatusCode> {
    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({})",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let result = client
        .execute(&stmt, &[&payload.title, &payload.description, &false])
        .await;

    match result {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// **Read User**
pub async fn get_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> Result<Json<Todo>, StatusCode> {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client
        .query_one(&stmt, &[&id])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user = Todo::from_row(&row);

    Ok(Json(user))
}

/// **Read Users**
pub async fn get_todos(
    State(db): State<Arc<Mutex<Client>>>,
) -> Result<Json<Vec<Todo>>, StatusCode> {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {}", TABLE);
    let rows = client
        .query(&stmt, &[])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let users = rows.iter().map(|row| Todo::from_row(row)).collect();

    Ok(Json(users))
}

/// **Update User**
pub async fn update_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<Todo>,
) -> Result<StatusCode, StatusCode> {
    let client = db.lock().await;

    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[
                &payload.title,
                &payload.description,
                &payload.completed,
                &id,
            ],
        )
        .await;

    match result {
        Ok(1) => Ok(StatusCode::OK),
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// **Delete User**
pub async fn delete_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let client = db.lock().await;

    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client.execute(&stmt, &[&id]).await;

    match result {
        Ok(1) => Ok(StatusCode::OK),
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
