use std::sync::Arc;

use crate::{
    models::{
        auth::{AuthRequest, AuthResponse},
        response::{ApiError, ApiResponse, AuthError},
        user::User,
    },
    utils::bcrypt::{compare_password, hash_password},
};
use actix_web::{
    http::StatusCode,
    web::{Data, Json},
    HttpResponse,
};
use regex::Regex;
use tokio::sync::Mutex;
use tokio_postgres::Client;

static TABLE: &str = "users";
static FIELDS: &str = "name, email, password, role";
static FIELDS_INPUT: &str = "$1, $2, $3, $4";

/// **Login User**
pub async fn login(
    client: Data<Arc<Mutex<Client>>>,
    payload: Json<AuthRequest>,
) -> Result<HttpResponse, ApiError> {
    match test_email(&client, payload.email.clone()).await {
        Ok(Some(user)) => {
            // test if password is right
            let is_equal = compare_password(&payload.password, &user.password).map_err(ApiError::from)?;
            match is_equal {
                false => Err(ApiError::Auth(AuthError::PasswordWrong)),
                true => {
                    // generate token
                    Ok(ApiResponse::success(
                        AuthResponse::user_to_response(user),
                        "Successfully logged in",
                        StatusCode::OK,
                    ))
                }
            }
        }
        Ok(None) => return Err(ApiError::Auth(AuthError::EmailWrong)),
        Err(err) => return Err(err),
    }
}

/// **Register User**
pub async fn register(
    client: Data<Arc<Mutex<Client>>>,
    payload: Json<AuthRequest>,
) -> Result<HttpResponse, ApiError> {
    match test_email(&client, payload.email.clone()).await {
        Ok(None) => {
            let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
                .map_err(|e| ApiError::RegexValidationError(format!("{}", e)))?;
            match email_regex.is_match(&payload.email) {
                false => return Err(ApiError::RegexValidationError("email invalid".to_string())),
                true => (),
            }
            let password_regex = Regex::new(r"^[A-Za-z0-9!@#$%^&*()_\-]{8,}$")
                .map_err(|e| ApiError::RegexValidationError(format!("{}", e)))?;
            match password_regex.is_match(&payload.password) {
                false => {
                    return Err(ApiError::RegexValidationError(
                        "password invalid".to_string(),
                    ))
                }
                true => (),
            }

            let client = client.lock().await;
            let stmt = format!(
                "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
                TABLE, FIELDS, FIELDS_INPUT
            );
            let hash = hash_password(&payload.password).map_err(ApiError::from)?;
            let role = payload.role.clone().unwrap_or_else(|| "user".to_string());
            let row = client
                .query_one(
                    &stmt,
                    &[&payload.name, &payload.email, &hash, &role],
                )
                .await
                .map_err(ApiError::from)?;

            let response = AuthResponse::row_to_response(row);
            Ok(ApiResponse::success(
                response,
                "User registered successfully",
                StatusCode::CREATED,
            ))
        }
        Ok(Some(_)) => Err(ApiError::Auth(AuthError::EmailTaken)),
        Err(err) => return Err(err),
    }
}

async fn test_email(client: &Arc<Mutex<Client>>, email: String) -> Result<Option<User>, ApiError> {
    let client = client.lock().await;
    let stmt = format!("SELECT * FROM {} WHERE email = $1", TABLE);
    match client.query_opt(&stmt, &[&email]).await {
        Ok(Some(row)) => Ok(Some(User::from_row(&row))),
        Ok(None) => Ok(None),
        Err(_) => Err(ApiError::Custom(
            "Error testing email existance".to_string(),
        )),
    }
}
