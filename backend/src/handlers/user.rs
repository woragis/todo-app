use std::sync::Arc;

use crate::{
    models::user::{CreateUser, UpdateUser, User},
    utils::response::{ApiError, ApiResponse},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
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
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );

    let row = client
        .query_one(&stmt, &[&payload.name, &payload.email, &payload.password])
        .await
        .map_err(ApiError::from)?;

    let user = User::from_row(&row);
    Ok(ApiResponse::success(
        user,
        "User created successfully",
        StatusCode::CREATED,
    ))
}

/// **Read User**
pub async fn get_user(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client
        .query_one(&stmt, &[&id])
        .await
        .map_err(ApiError::from)?;

    let user = User::from_row(&row);
    Ok(ApiResponse::success(
        user,
        "User retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Read Users**
pub async fn get_users(
    State(db): State<Arc<Mutex<Client>>>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let stmt = format!("SELECT * FROM {}", TABLE);
    let rows = client.query(&stmt, &[]).await.map_err(ApiError::from)?;

    let users: Vec<User> = rows.iter().map(User::from_row).collect();
    Ok(ApiResponse::success(
        users,
        "Users retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Update User**
pub async fn update_user(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateUser>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &payload.password, &id],
        )
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        let updated_user = User {
            id,
            name: payload.name,
            email: payload.email,
            password: payload.password,
        };
        return Ok(ApiResponse::success(
            updated_user,
            "User updated successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found on update".to_string()));
    }

    Err(ApiError::Custom("Unexpected update count".to_string()))
}

/// **Delete User**
pub async fn delete_user(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client
        .execute(&stmt, &[&id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            id.to_string(),
            "User deleted successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found".to_string()));
    }

    Err(ApiError::Custom("Unexpected delete count".to_string()))
}
