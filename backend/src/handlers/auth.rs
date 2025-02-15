use std::sync::Arc;

use crate::{
    models::auth::{AuthRequest, AuthResponse},
    utils::response::{ApiError, ApiResponse},
};
use axum::{extract::State, http::StatusCode, Json};
use tokio::sync::Mutex;
use tokio_postgres::Client;

static TABLE: &str = "users";
static FIELDS: &str = "email, password";
static FIELDS_INPUT: &str = "$1, $2";

/// **Login User**
pub async fn login(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<AuthRequest>,
) -> (StatusCode, Json<ApiResponse<AuthResponse>>) {
    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let result = client
        .query_one(&stmt, &[&payload.email, &payload.password])
        .await;

    match result {
        Ok(row) => ApiResponse::success(
            AuthResponse::row_to_response(row),
            "User registered successfully",
            StatusCode::CREATED,
        ),
        Err(error) => ApiResponse::error(
            "Failed to login",
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            ApiError::Database(error),
        ),
    }
}

/// **Register User**
pub async fn register(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<AuthRequest>,
) -> (StatusCode, Json<ApiResponse<AuthResponse>>) {
    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let result = client
        .query_one(&stmt, &[&payload.email, &payload.password])
        .await;

    match result {
        Ok(row) => ApiResponse::success(
            AuthResponse::row_to_response(row),
            "User logged in successfully",
            StatusCode::CREATED,
        ),
        Err(error) => ApiResponse::error(
            "Failed to register",
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            ApiError::Database(error),
        ),
    }
}
