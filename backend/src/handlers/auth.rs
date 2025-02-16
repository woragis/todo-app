use std::sync::Arc;

use crate::{
    models::auth::{AuthRequest, AuthResponse},
    utils::response::{ApiError, ApiResponse},
};
use axum::{extract::State, http::StatusCode, Json};
use tokio::sync::Mutex;
use tokio_postgres::Client;

static TABLE: &str = "users";
static FIELDS: &str = "name, email, password";
static FIELDS_INPUT: &str = "$1, $2, $3";

/// **Login User**
pub async fn login(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<AuthRequest>,
) -> (StatusCode, Json<ApiResponse<AuthResponse>>) {
    println!("Login request received for email: {}", payload.email);

    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {} WHERE email = $1", TABLE);
    let result = client.query_one(&stmt, &[&payload.email]).await;

    match result {
        Ok(row) => {
            println!("User found in database");
            ApiResponse::success(
                AuthResponse::row_to_response(row),
                "User logged in successfully",
                StatusCode::OK,
            )
        }
        Err(error) => {
            println!("Database query error: {:?}", error);
            ApiResponse::error(
                "Failed to login",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
                ApiError::Database(error),
            )
        }
    }
}


/// **Register User**
pub async fn register(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<AuthRequest>,
) -> (StatusCode, Json<ApiResponse<AuthResponse>>) {
    println!("Register request received for email: {}", payload.email);

    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let result = client
        .query_one(&stmt, &[&"_",&payload.email, &payload.password])
        .await;

    match result {
        Ok(row) => {
            println!("User registered successfully");
            ApiResponse::success(
                AuthResponse::row_to_response(row),
                "User registered successfully",
                StatusCode::CREATED,
            )
        }
        Err(error) => {
            println!("Database insertion error: {:?}", error);
            ApiResponse::error(
                "Failed to register",
                StatusCode::INTERNAL_SERVER_ERROR,
                1,
                ApiError::Database(error),
            )
        }
    }
}
