use std::fmt;

use actix_web::{error::ResponseError, http::StatusCode, HttpResponse, Responder};
use bcrypt::BcryptError;
use deadpool_redis::{redis::RedisError, PoolError};
use jsonwebtoken::errors::Error as JwtError;
use serde::Serialize;
use serde_json::Error as SerdeJsonError;
use tokio_postgres::Error as PgError;
use uuid::Error as UuidError;

// API Response
#[derive(Serialize)]
pub struct ApiResponse<T> {
    data: Option<T>,
    message: String,
    error: u16,
}

// Define a custom error type
#[derive(Debug)]
pub enum AuthError {
    AdminsOnly,
    MissingHeader,
    InvalidHeader,
    MissingBearer,
    PasswordWrong,
    EmailTaken,
    EmailWrong,
}

// Implement `Display` for `AuthError`
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::AdminsOnly => write!(f, "Admin only section"),
            AuthError::MissingHeader => write!(f, "Authorization header is missing"),
            AuthError::InvalidHeader => write!(f, "Invalid authorization header format"),
            AuthError::MissingBearer => write!(f, "Error striping 'Bearer '"),
            AuthError::PasswordWrong => write!(f, "Password wrong"),
            AuthError::EmailTaken => write!(f, "Email is already taken"),
            AuthError::EmailWrong => write!(f, "Email wrong"),
        }
    }
}

// Define a custom error type
#[derive(Debug)]
pub enum ApiError {
    Jwt(JwtError),
    OpenSSL(openssl::error::Error),
    Bcrypt(BcryptError),
    Database(PgError),
    Redis(RedisError),
    RedisPool(PoolError),
    SerdeJson(SerdeJsonError),
    Uuid(UuidError),
    Auth(AuthError),
    TooManyRequests,
    RegexValidationError(String),
    Custom(String),
}

// Implement `Display` for pretty-printing
impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Jwt(e) => write!(f, "JWT error: {}", e),
            ApiError::OpenSSL(e) => write!(f, "OpenSSL error: {}", e),
            ApiError::Bcrypt(e) => write!(f, "Bcrypt error: {}", e),
            ApiError::Database(e) => write!(f, "Database error: {}", e),
            ApiError::Redis(e) => write!(f, "Redis error: {}", e),
            ApiError::RedisPool(e) => write!(f, "Redis pool error: {}", e),
            ApiError::SerdeJson(e) => write!(f, "Serialization error: {}", e),
            ApiError::Uuid(e) => write!(f, "UUID error: {}", e),
            ApiError::Auth(e) => write!(f, "Auth error: {}", e),
            ApiError::TooManyRequests => write!(f, "Too many requests"),
            ApiError::RegexValidationError(msg) => write!(f, "Regex validation error: {}", msg),
            ApiError::Custom(msg) => write!(f, "Custom error: {}", msg),
        }
    }
}

// Implement Actix's `ResponseError` for `ApiError`
impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Jwt(_) => StatusCode::UNAUTHORIZED, // 401
            ApiError::OpenSSL(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::Bcrypt(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::Redis(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::RedisPool(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::SerdeJson(_) => StatusCode::BAD_REQUEST, // 400
            ApiError::Uuid(_) => StatusCode::BAD_REQUEST, // 400
            ApiError::Auth(auth_error) => match auth_error {
                AuthError::AdminsOnly => StatusCode::UNAUTHORIZED, // 401
                AuthError::MissingHeader => StatusCode::UNAUTHORIZED, // 401
                AuthError::InvalidHeader => StatusCode::BAD_REQUEST, // 400
                AuthError::MissingBearer => StatusCode::BAD_REQUEST, // 400
                AuthError::PasswordWrong => StatusCode::BAD_REQUEST, // 400
                AuthError::EmailTaken => StatusCode::BAD_REQUEST,  // 400
                AuthError::EmailWrong => StatusCode::BAD_REQUEST,  // 400
            },
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS, // 429
            ApiError::RegexValidationError(_) => StatusCode::BAD_REQUEST, // 400
            ApiError::Custom(_) => StatusCode::BAD_REQUEST,             // 400
        }
    }

    fn error_response(&self) -> HttpResponse {
        let error_number = match self {
            ApiError::Auth(AuthError::AdminsOnly) => 1007,
            ApiError::Auth(AuthError::MissingHeader) => 1001,
            ApiError::Auth(AuthError::InvalidHeader) => 1002,
            ApiError::Auth(AuthError::MissingBearer) => 1003,
            ApiError::Auth(AuthError::PasswordWrong) => 1004,
            ApiError::Auth(AuthError::EmailTaken) => 1005,
            ApiError::Auth(AuthError::EmailWrong) => 1006,
            ApiError::Jwt(_) => 2001,
            ApiError::OpenSSL(_) => 2003,
            ApiError::Bcrypt(_) => 2002,
            ApiError::Database(_) => 3001,
            ApiError::Redis(_) => 3002,
            ApiError::RedisPool(_) => 3003,
            ApiError::SerdeJson(_) => 4002,
            ApiError::Uuid(_) => 4001,
            ApiError::TooManyRequests => 4290,
            ApiError::RegexValidationError(_) => 1000,
            ApiError::Custom(_) => 5001,
        };

        let response = ApiResponse::<()> {
            data: None,
            message: self.to_string(),
            error: error_number,
        };

        HttpResponse::build(self.status_code()).json(response)
    }
}

// Convert other errors into `ApiError`
impl From<JwtError> for ApiError {
    fn from(err: JwtError) -> Self {
        log::error!("JWT error: {}", err);
        ApiError::Jwt(err)
    }
}

impl From<openssl::error::Error> for ApiError {
    fn from(err: openssl::error::Error) -> Self {
        log::error!("OpenSSL error: {}", err);
        ApiError::OpenSSL(err)
    }
}

impl From<BcryptError> for ApiError {
    fn from(err: BcryptError) -> Self {
        log::error!("Bcrypt error: {}", err);
        ApiError::Bcrypt(err)
    }
}

impl From<PgError> for ApiError {
    fn from(err: PgError) -> Self {
        log::error!("Postgres error: {}", err);
        ApiError::Database(err)
    }
}

impl From<RedisError> for ApiError {
    fn from(err: RedisError) -> Self {
        log::error!("Redis error: {}", err);
        ApiError::Redis(err)
    }
}

impl From<PoolError> for ApiError {
    fn from(err: PoolError) -> Self {
        log::error!("Redis Pool error: {}", err);
        ApiError::RedisPool(err)
    }
}

impl From<SerdeJsonError> for ApiError {
    fn from(err: SerdeJsonError) -> Self {
        log::error!("SerdeJson error: {}", err);
        ApiError::SerdeJson(err)
    }
}

impl From<UuidError> for ApiError {
    fn from(err: UuidError) -> Self {
        log::error!("Uuid error: {}", err);
        ApiError::Uuid(err)
    }
}

impl From<AuthError> for ApiError {
    fn from(err: AuthError) -> Self {
        log::error!("Auth error: {}", err);
        ApiError::Auth(err)
    }
}

// Success response method for API responses
impl<T> ApiResponse<T> {
    pub fn success(data: T, message: &str, status: StatusCode) -> HttpResponse
    where
        T: Serialize,
    {
        HttpResponse::build(status).json(Self {
            data: Some(data),
            message: message.to_string(),
            error: 0,
        })
    }
}

// Implement `Responder` for `ApiResponse<T>` to convert the success response to JSON
impl<T> Responder for ApiResponse<T>
where
    T: Serialize,
{
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _: &actix_web::HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok().json(self)
    }
}
