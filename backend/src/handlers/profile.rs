use std::sync::Arc;

use crate::{
    models::user::{UpdateUser, User},
    utils::{
        jwt::{validate_auth, validate_jwt},
        response::{ApiError, ApiResponse},
    },
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "users";
static UPDATE_FIELDS: &str = "name = $1, email = $2, password = $3";

/// **Read User**
pub async fn get_user_profile(
    State(db): State<Arc<Mutex<Client>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<ApiResponse<User>>) {
    let client = db.lock().await;

    let auth_token = match validate_auth(&headers) {
        Ok(token) => token,
        Err(error) => {
            return ApiResponse::<User>::error(
                "Invalid authorization header",
                StatusCode::UNAUTHORIZED,
                2,
                ApiError::Auth(error),
            )
        }
    };

    let validated_token = match validate_jwt(&auth_token) {
        Ok(token) => token,
        Err(error) => {
            return ApiResponse::<User>::error(
                "Invalid JWT token",
                StatusCode::UNAUTHORIZED,
                3,
                ApiError::Jwt(error),
            )
        }
    };

    let id = validated_token.sub;

    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client.query_one(&stmt, &[&id]).await;

    match row {
        Ok(row) => {
            let user = User::from_row(&row);
            ApiResponse::success(user, "User retrieved successfully", StatusCode::OK)
        }
        Err(error) => ApiResponse::error(
            "User not found",
            StatusCode::NOT_FOUND,
            2,
            ApiError::Database(error),
        ),
    }
}

/// **Update User**
pub async fn update_user_profile(
    State(db): State<Arc<Mutex<Client>>>,
    headers: HeaderMap,
    Json(payload): Json<UpdateUser>,
) -> (StatusCode, Json<ApiResponse<User>>) {
    let client = db.lock().await;
    let auth_token = match validate_auth(&headers) {
        Ok(token) => token,
        Err(error) => {
            return ApiResponse::<User>::error(
                "Invalid authorization header",
                StatusCode::UNAUTHORIZED,
                2,
                ApiError::Auth(error),
            )
        }
    };

    let validated_token = match validate_jwt(&auth_token) {
        Ok(token) => token,
        Err(error) => {
            return ApiResponse::<User>::error(
                "Invalid JWT token",
                StatusCode::UNAUTHORIZED,
                3,
                ApiError::Jwt(error),
            )
        }
    };

    let id_str = validated_token.sub;
    let id = match Uuid::parse_str(&id_str) {
        Ok(id) => id,
        Err(error) => {
            return ApiResponse::<User>::error(
                "Error parsing uuid",
                StatusCode::INTERNAL_SERVER_ERROR,
                4,
                ApiError::Uuid(error),
            )
        }
    };

    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &payload.password, &id_str],
        )
        .await;

    let updated_user = User {
        id: id,
        name: payload.name,
        email: payload.email,
        password: payload.password,
    };
    match result {
        Ok(1) => ApiResponse::success(updated_user, "User updated successfully", StatusCode::OK),
        Ok(0) => ApiResponse::error(
            "User not found",
            StatusCode::NOT_FOUND,
            4,
            ApiError::Custom("User not found on update".to_string()),
        ),
        Ok(n) => ApiResponse::error(
            &format!("Unexpected update count: {}", n),
            StatusCode::INTERNAL_SERVER_ERROR,
            6,
            ApiError::Custom("Unexpected Error".to_string()),
        ), // Handles cases where more than 1 row is affected (shouldn't happen)
        Err(error) => ApiResponse::error(
            "Failed to update user",
            StatusCode::INTERNAL_SERVER_ERROR,
            5,
            ApiError::Database(error),
        ),
    }
}

/// **Delete User**
pub async fn delete_user_profile(
    State(db): State<Arc<Mutex<Client>>>,
    headers: HeaderMap,
) -> (StatusCode, Json<ApiResponse<String>>) {
    let client = db.lock().await;

    let auth_token = match validate_auth(&headers) {
        Ok(token) => token,
        Err(error) => {
            return ApiResponse::<String>::error(
                "Invalid authorization header",
                StatusCode::UNAUTHORIZED,
                2,
                ApiError::Auth(error),
            )
        }
    };

    let validated_token = match validate_jwt(&auth_token) {
        Ok(token) => token,
        Err(error) => {
            return ApiResponse::<String>::error(
                "Invalid JWT token",
                StatusCode::UNAUTHORIZED,
                3,
                ApiError::Jwt(error),
            )
        }
    };

    let id = validated_token.sub;

    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client.execute(&stmt, &[&id]).await;

    match result {
        Ok(1) => ApiResponse::success(id.to_string(), "User deleted successfully", StatusCode::OK),
        Ok(0) => ApiResponse::error(
            "User not found",
            StatusCode::NOT_FOUND,
            4,
            ApiError::Custom("User not found on update".to_string()),
        ),
        Ok(n) => ApiResponse::error(
            &format!("Unexpected update count: {}", n),
            StatusCode::INTERNAL_SERVER_ERROR,
            6,
            ApiError::Custom("Unexpected Error".to_string()),
        ), // Handles cases where more than 1 row is affected (shouldn't happen)
        Err(error) => ApiResponse::error(
            "Failed to update user",
            StatusCode::INTERNAL_SERVER_ERROR,
            5,
            ApiError::Database(error),
        ),
    }
}
