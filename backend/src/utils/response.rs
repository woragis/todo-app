use axum::{http::StatusCode, Json};
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

// Implement `From<T>` to convert other errors into `ApiError`
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

    pub fn error(
        message: &str,
        status: StatusCode,
        error_number: u16,
        error: ApiError,
    ) -> (StatusCode, Json<Self>) {
        println!("Error: {}", error); // Log the error

        (
            status,
            Json(Self {
                status_code: status.as_u16(),
                data: None,
                message: format!("{}: {}", message, error), // Include error details in response
                error: error_number,
            }),
        )
    }
}
