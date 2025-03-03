use actix_web::http::header::HeaderMap;
use chrono::{Duration, Utc};
use dotenvy::dotenv;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use log::debug;
use once_cell::sync::Lazy;
use std::env;
use uuid::Uuid;

use crate::models::{jwt::Claims, response::AuthError};

static SECRET_KEY: Lazy<String> = Lazy::new(|| {
    dotenv().ok();
    debug!("Fetching jwt SECRET_KEY...");
    env::var("SECRET_KEY").expect("SECRET_KEY must be set")
});

pub fn generate_jwt(user_id: Uuid, role: String) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(60))
        .expect("JWT Generation: error in timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_string(),
        role,
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
            Ok(auth_str) => match auth_str.strip_prefix("Bearer ") {
                Some(token) => Ok(token.to_string()),
                None => Err(AuthError::MissingBearer),
            },
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
