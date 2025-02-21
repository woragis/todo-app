use std::sync::Arc;

use crate::{
    models::auth::{AuthRequest, AuthResponse},
    utils::response::{ApiError, ApiResponse},
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tokio::sync::Mutex;
use tokio_postgres::Client;

static TABLE: &str = "users";
static FIELDS: &str = "name, email, password";
static FIELDS_INPUT: &str = "$1, $2, $3";

/// **Login User**
pub async fn login(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, ApiError> {
    println!("Login request received for email: {}", payload.email);

    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {} WHERE email = $1", TABLE);
    let row = client
        .query_one(&stmt, &[&payload.email])
        .await
        .map_err(ApiError::from)?;

    println!("User found in database");

    let response = AuthResponse::row_to_response(row);
    Ok(ApiResponse::success(
        response,
        "User logged in successfully",
        StatusCode::OK,
    ))
}

/// **Register User**
pub async fn register(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<AuthRequest>,
) -> Result<impl IntoResponse, ApiError> {
    println!("Register request received for email: {}", payload.email);

    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let row = client
        .query_one(&stmt, &[&payload.name, &payload.email, &payload.password])
        .await
        .map_err(ApiError::from)?;

    println!("User registered successfully");

    let response = AuthResponse::row_to_response(row);
    Ok(ApiResponse::success(
        response,
        "User registered successfully",
        StatusCode::CREATED,
    ))
}
