use std::sync::Arc;

use crate::{
    models::{
        response::{ApiError, ApiResponse, AuthError},
        user::{User, UserAuthRequest, UserAuthResponse},
    },
    utils::{bcrypt::{compare_password, hash_password}, encryption::{aes_encrypt_string, sha_encrypt_string}, regex::{regex_email, regex_password}},
};
use actix_web::{
    http::StatusCode,
    web::{Data, Json},
    HttpResponse,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;

static TABLE: &str = "users";

/// **Login User**
pub async fn login(
    client: Data<Arc<Mutex<Client>>>,
    payload: Json<UserAuthRequest>,
) -> Result<HttpResponse, ApiError> {
    let email_hash = sha_encrypt_string(payload.email.to_owned()).map_err(ApiError::from)?;
    match test_email(&client, email_hash).await {
        Ok(Some(user)) => {
            // test if password is right
            let is_equal = compare_password(&payload.password, &user.password).map_err(ApiError::from)?;
            match is_equal {
                false => Err(ApiError::Auth(AuthError::PasswordWrong)),
                true => {
                    // generate token
                    Ok(ApiResponse::success(
                        UserAuthResponse::user_to_response(user),
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
    payload: Json<UserAuthRequest>,
) -> Result<HttpResponse, ApiError> {
    let email_hash = sha_encrypt_string(payload.email.to_owned()).map_err(ApiError::from)?;
    match test_email(&client, email_hash.clone()).await {
        Ok(None) => {
            regex_email(&payload.email)?;
            regex_password(&payload.password)?;

            let client = client.lock().await;
            let fields = "name, email_hash, email_encrypt, nonce, password, role";
            let inputs = "$1, $2, $3, $4, $5, $6";
            let email_encrypt = aes_encrypt_string(payload.email.clone());
            let email_encrypt = hex::encode(email_encrypt);
            let password_hash = hash_password(&payload.password).map_err(ApiError::from)?;
            let role = payload.role.clone().unwrap_or_else(|| "user".to_string());
            let stmt = format!(
                "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
                TABLE, fields, inputs
            );
            let row = client
                .query_one(
                    &stmt,
                    &[
                        &payload.name,
                        &email_hash.to_owned(),
                        &email_encrypt,
                        &"null".to_string(),
                        &password_hash,
                        &role,
                    ],
                )
                .await
                .map_err(ApiError::from)?;

            let response = UserAuthResponse::row_to_response(row);
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

async fn test_email(client: &Arc<Mutex<Client>>, email_hash: String) -> Result<Option<User>, ApiError> {
    let client = client.lock().await;
    let stmt = format!("SELECT * FROM {} WHERE email_hash = $1", TABLE);
    match client.query_opt(&stmt, &[&email_hash]).await {
        Ok(Some(row)) => Ok(Some(User::from_row(&row))),
        Ok(None) => Ok(None),
        Err(_) => Err(ApiError::Custom(
            "Error testing email existance".to_string(),
        )),
    }
}
