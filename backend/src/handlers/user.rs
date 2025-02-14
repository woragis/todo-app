use std::sync::Arc;

use crate::{
    models::user::{CreateUser, UpdateUser, User},
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

static TABLE: &str = "users";
static FIELDS: &str = "name, email, password";
static UPDATE_FIELDS: &str = "name = $1, email = $2, password = $3";
static FIELDS_INPUT: &str = "$1, $2, $3";

/// **Create User**
pub async fn create_user(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<CreateUser>,
) -> (StatusCode, Json<ApiResponse<User>>) {
    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let result = client
        .query_one(&stmt, &[&payload.name, &payload.email, &payload.password])
        .await;

    match result {
        Ok(row) => {
            let user = User::from_row(&row);
            ApiResponse::success(user, "User created successfully", StatusCode::CREATED)
        }
        Err(_) => ApiResponse::error(
            "Failed to create user",
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
        ),
    }
}

/// **Read User**
pub async fn get_user(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> (StatusCode, Json<ApiResponse<User>>) {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client.query_one(&stmt, &[&id]).await;

    match row {
        Ok(row) => {
            let user = User::from_row(&row);
            ApiResponse::success(user, "User retrieved successfully", StatusCode::OK)
        }
        Err(_) => ApiResponse::error("User not found", StatusCode::NOT_FOUND, 2),
    }
}

/// **Read Users**
pub async fn get_users(
    State(db): State<Arc<Mutex<Client>>>,
) -> (StatusCode, Json<ApiResponse<Vec<User>>>) {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {}", TABLE);
    let rows = client.query(&stmt, &[]).await;

    match rows {
        Ok(rows) => {
            let users = rows.iter().map(|row| User::from_row(row)).collect();
            ApiResponse::success(users, "Users retrieved successfully", StatusCode::OK)
        }
        Err(_) => ApiResponse::error(
            "Failed to retrieve users",
            StatusCode::INTERNAL_SERVER_ERROR,
            3,
        ),
    }
}

/// **Update User**
pub async fn update_user(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateUser>,
) -> (StatusCode, Json<ApiResponse<User>>) {
    let client = db.lock().await;

    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &payload.password, &id],
        )
        .await;

    let updated_user = User{
        id: id,
        name: payload.name,
        email: payload.email,
        password: payload.password
    };
    match result {
        Ok(1) => ApiResponse::success(updated_user, "User updated successfully", StatusCode::OK),
        Ok(0) => ApiResponse::error("User not found", StatusCode::NOT_FOUND, 4),
        Ok(n) => ApiResponse::error(
            &format!("Unexpected update count: {}", n),
            StatusCode::INTERNAL_SERVER_ERROR,
            6,
        ), // Handles cases where more than 1 row is affected (shouldn't happen)
        Err(_) => ApiResponse::error(
            "Failed to update user",
            StatusCode::INTERNAL_SERVER_ERROR,
            5,
        ),
    }
}

/// **Delete User**
pub async fn delete_user(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let client = db.lock().await;

    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client.execute(&stmt, &[&id]).await;

    match result {
        Ok(1) => ApiResponse::success(id.to_string(), "User deleted successfully", StatusCode::OK),
        Ok(_) => ApiResponse::error("User not found", StatusCode::NOT_FOUND, 6),
        Err(_) => ApiResponse::error(
            "Failed to delete user",
            StatusCode::INTERNAL_SERVER_ERROR,
            7,
        ),
    }
}
