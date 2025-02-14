use std::sync::Arc;

use crate::{
    models::todo::{CreateTodo, Todo, UpdateTodo},
    utils::response::ApiResponse,
};
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

/// **Create Todo**
pub async fn create_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<CreateTodo>,
) -> (StatusCode, Json<ApiResponse<Todo>>) {
    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let result = client
        .query_one(&stmt, &[&payload.title, &payload.description, &false])
        .await;

    match result {
        Ok(row) => {
            let todo = Todo::from_row(&row);
            ApiResponse::success(todo, "Todo created successfully", StatusCode::CREATED)
        }
        Err(_) => ApiResponse::error(
            "Failed to create todo",
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
        ),
    }
}

/// **Read Todo**
pub async fn get_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> (StatusCode, Json<ApiResponse<Todo>>) {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client.query_one(&stmt, &[&id]).await;

    match row {
        Ok(row) => {
            let todo = Todo::from_row(&row);
            ApiResponse::success(todo, "Todo retrieved successfully", StatusCode::OK)
        }
        Err(_) => ApiResponse::error("Todo not found", StatusCode::NOT_FOUND, 2),
    }
}

/// **Read Todos**
pub async fn get_todos(
    State(db): State<Arc<Mutex<Client>>>,
) -> (StatusCode, Json<ApiResponse<Vec<Todo>>>) {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {}", TABLE);
    let rows = client.query(&stmt, &[]).await;

    match rows {
        Ok(rows) => {
            let todos = rows.iter().map(|row| Todo::from_row(row)).collect();
            ApiResponse::success(todos, "Todos retrieved successfully", StatusCode::OK)
        }
        Err(_) => ApiResponse::error(
            "Failed to retrieve todos",
            StatusCode::INTERNAL_SERVER_ERROR,
            3,
        ),
    }
}

/// **Update Todo**
pub async fn update_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateTodo>,
) -> (StatusCode, Json<ApiResponse<Todo>>) {
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
    

    let updated_todo = Todo{
        id: id,
        title: payload.title,
        description: payload.description,
        completed: payload.completed,
    };
    match result {
        Ok(1) => ApiResponse::success(updated_todo, "Todo updated successfully", StatusCode::OK),
        Ok(0) => ApiResponse::error("Todo not found", StatusCode::NOT_FOUND, 4),
        Ok(n) => ApiResponse::error(
            &format!("Unexpected update count: {}", n),
            StatusCode::INTERNAL_SERVER_ERROR,
            6,
        ), // Handles cases where more than 1 row is affected (shouldn't happen)
        Err(_) => ApiResponse::error(
            "Failed to update todo",
            StatusCode::INTERNAL_SERVER_ERROR,
            5,
        ),
    }
}

/// **Delete Todo**
pub async fn delete_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let client = db.lock().await;

    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client.execute(&stmt, &[&id]).await;

    match result {
        Ok(1) => ApiResponse::success(id.to_string(), "Todo deleted successfully", StatusCode::OK),
        Ok(_) => ApiResponse::error("Todo not found", StatusCode::NOT_FOUND, 6),
        Err(_) => ApiResponse::error(
            "Failed to delete todo",
            StatusCode::INTERNAL_SERVER_ERROR,
            7,
        ),
    }
}
