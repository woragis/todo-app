use axum::{http::StatusCode, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct ApiResponse<T> {
    status_code: u16,
    data: Option<T>,
    message: String,
    error: u16,
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

    pub fn error(message: &str, status: StatusCode, error: u16) -> (StatusCode, Json<Self>) {
        (
            status,
            Json(Self {
                status_code: status.as_u16(),
                data: None,
                message: message.to_string(),
                error,
            }),
        )
    }
}
