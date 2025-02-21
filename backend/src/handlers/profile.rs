use std::sync::Arc;

use crate::{
    models::user::{UpdateUser, User},
    utils::{
        jwt::{extract_token, validate_jwt},
        response::{ApiError, ApiResponse},
    },
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "users";
static UPDATE_FIELDS: &str = "name = $1, email = $2, password = $3";

/// **Read User Profile**
pub async fn get_user_profile(
    State(db): State<Arc<Mutex<Client>>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let auth_token = extract_token(&headers).map_err(ApiError::Auth)?;
    let validated_token = validate_jwt(&auth_token).map_err(ApiError::Jwt)?;
    let id = validated_token.sub;

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

/// **Update User Profile**
pub async fn update_user_profile(
    State(db): State<Arc<Mutex<Client>>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateUser>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let auth_token = extract_token(&headers).map_err(ApiError::Auth)?;
    let validated_token = validate_jwt(&auth_token).map_err(ApiError::Jwt)?;
    let id = Uuid::parse_str(&validated_token.sub).map_err(ApiError::Uuid)?;

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
        return Err(ApiError::Custom("User not found".to_string()));
    }

    Err(ApiError::Custom("Unexpected update count".to_string()))
}

/// **Delete User Profile**
pub async fn delete_user_profile(
    State(db): State<Arc<Mutex<Client>>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    let auth_token = extract_token(&headers).map_err(ApiError::Auth)?;
    let validated_token = validate_jwt(&auth_token).map_err(ApiError::Jwt)?;
    let id = validated_token.sub;

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
