use crate::models::jwt::Claims;
use actix_web::http::header::HeaderMap;
use chrono::{Duration, Utc};
use dotenvy::dotenv;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use uuid::Uuid;
use std::env;
use std::fmt;

// Define a custom error type
#[derive(Debug)]
pub enum AuthError {
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
            AuthError::MissingHeader => write!(f, "Authorization header is missing"),
            AuthError::InvalidHeader => write!(f, "Invalid authorization header format"),
            AuthError::MissingBearer => write!(f, "Error striping 'Bearer '"),
            AuthError::PasswordWrong => write!(f, "Password wrong"),
            AuthError::EmailTaken => write!(f, "Email is already taken"),
            AuthError::EmailWrong => write!(f, "Email wrong"),
        }
    }
}

static SECRET_KEY: Lazy<String> = Lazy::new(|| {
    dotenv().ok(); // Load .env file if available
    env::var("SECRET_KEY").expect("SECRET_KEY must be set")
});

pub fn generate_jwt(user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(60))
        .expect("Valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(SECRET_KEY.as_ref()),
    )
}

pub fn extract_token(header: &HeaderMap) -> Result<String, AuthError> {
    match header.get("Authorization") {
        Some(auth_header) => match auth_header.to_str() {
            Ok(auth_str) => {
                println!("Authorization Header: {}", auth_str);
                match auth_str.strip_prefix("Bearer ") {
                    Some(token) => Ok(token.to_string()),
                    None => Err(AuthError::MissingBearer),
                }
            }
            Err(_) => Err(AuthError::InvalidHeader),
        },
        None => Err(AuthError::MissingHeader),
    }
}

pub fn validate_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET_KEY.as_ref()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}
