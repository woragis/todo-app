use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
use jsonwebtoken::errors::Error as JwtError;
use serde::Serialize;
use std::fmt;
use tokio_postgres::Error as PgError;
use uuid::Error as UuidError;

use super::jwt::AuthError;

// API Response
#[derive(Serialize)]
pub struct ApiResponse<T> {
    status_code: u16,
    data: Option<T>,
    message: String,
    error: u16,
}

// Define a custom error type manually
#[derive(Debug)]
pub enum ApiError {
    Jwt(JwtError),
    Database(PgError),
    Uuid(UuidError),
    Auth(AuthError),
    Custom(String),
}

// Implement `Display` for pretty-printing
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Jwt(e) => write!(f, "JWT error: {}", e),
            ApiError::Database(e) => write!(f, "Database error: {}", e),
            ApiError::Uuid(e) => write!(f, "UUID error: {}", e),
            ApiError::Auth(e) => write!(f, "Auth error: {}", e),
            ApiError::Custom(msg) => write!(f, "Custom error: {}", msg),
        }
    }
}

// Map `ApiError` to HTTP status codes
impl ApiError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Jwt(_) => StatusCode::UNAUTHORIZED, // 401
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::Uuid(_) => StatusCode::BAD_REQUEST, // 400
            ApiError::Auth(auth_error) => match auth_error {
                AuthError::MissingHeader => StatusCode::UNAUTHORIZED, // 401
                AuthError::InvalidHeader => StatusCode::BAD_REQUEST,  // 400
                AuthError::MissingBearer => StatusCode::BAD_REQUEST,  // 400
            },
            ApiError::Custom(_) => StatusCode::BAD_REQUEST, // 400
        }
    }
}

// Convert other errors into `ApiError`
impl From<JwtError> for ApiError {
    fn from(err: JwtError) -> Self {
        ApiError::Jwt(err)
    }
}

impl From<PgError> for ApiError {
    fn from(err: PgError) -> Self {
        ApiError::Database(err)
    }
}

impl From<UuidError> for ApiError {
    fn from(err: UuidError) -> Self {
        ApiError::Uuid(err)
    }
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        ApiError::Auth(err)
    }
}

// Implement `IntoResponse` for `ApiError` to return JSON responses
impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status_code();

        let error_number = match self {
            ApiError::Auth(AuthError::MissingHeader) => 1001,
            ApiError::Auth(AuthError::InvalidHeader) => 1002,
            ApiError::Auth(AuthError::MissingBearer) => 1003,
            ApiError::Jwt(_) => 2001,
            ApiError::Database(_) => 3001,
            ApiError::Uuid(_) => 4001,
            ApiError::Custom(_) => 5001,
        };

        let response = ApiResponse::<()> {
            status_code: status.as_u16(),
            data: None,
            message: self.to_string(),
            error: error_number,
        };

        (status, Json(response)).into_response()
    }
}

// Success response method for API responses
impl<T> ApiResponse<T> {
    pub fn success(data: T, message: &str, status: StatusCode) -> (StatusCode, Json<Self>) {
        (
            status,
            Json(Self {
                status_code: status.as_u16(),
                data: Some(data),
                message: message.to_string(),
                error: 0,
            }),
        )
    }
}
