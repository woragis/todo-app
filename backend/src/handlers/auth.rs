use std::{str::FromStr, sync::Arc};

use actix_web::{
    http::StatusCode,
    web::{Data, Json},
    HttpRequest, HttpResponse,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

use crate::{
    models::{
        response::{ApiError, ApiResponse, AuthError},
        user::{UpdateProfile, User, UserAuthRequest, UserAuthResponse, UserUpdatePassword},
    },
    utils::{
        bcrypt::{compare_password, hash_password},
        encryption::{aes_encrypt_string, sha_encrypt_string},
        jwt::{extract_token, validate_jwt},
        regex::{regex_email, regex_password},
    },
};

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
            log::debug!("User password: {}", &payload.password);
            log::debug!("DB password: {}", &user.password);
            let is_equal = compare_password(&payload.password, &user.password)?;
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
            let password_hash = hash_password(&payload.password)?;
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

async fn test_email(
    client: &Arc<Mutex<Client>>,
    email_hash: String,
) -> Result<Option<User>, ApiError> {
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

/// **Read User Profile**
pub async fn get_user_profile(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client
        .query_one(&stmt, &[&user_id])
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
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
    payload: Json<UpdateProfile>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    regex_email(&payload.email)?;

    let client = client.lock().await;
    let stmt = format!("UPDATE {} SET name = $1, email = $2 WHERE id = $3", TABLE);
    let result = client
        .execute(&stmt, &[&payload.name, &payload.email, &user_id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            (),
            "User updated successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found".to_string()));
    }
    Err(ApiError::Custom("Unexpected update count".to_string()))
}

/// **Update User Password**
pub async fn update_user_password(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
    payload: Json<UserUpdatePassword>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let is_equal = compare_password(&payload.old_password, &payload.new_password)?;
    match is_equal {
        false => return Err(ApiError::Auth(AuthError::PasswordWrong)),
        true => ()
    }

    regex_password(&payload.new_password)?;
    let hashed_password = hash_password(&payload.new_password)?;

    let client = client.lock().await;
    let stmt = format!("UPDATE {} SET password = $1 WHERE id = $2", TABLE);
    let result = client
        .execute(&stmt, &[&hashed_password, &user_id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            (),
            "Password updated successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found".to_string()));
    }
    Err(ApiError::Custom("Unexpected update count".to_string()))
}

/// **Delete User Profile**
pub async fn delete_user_profile(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client
        .execute(&stmt, &[&user_id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            (),
            "Account deleted successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found".to_string()));
    }
    Err(ApiError::Custom("Unexpected delete count".to_string()))
}

pub async fn get_profile_picture(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("SELECT profile_picture FROM {} WHERE id = $1", TABLE);
    let row = client
        .query_opt(&stmt, &[&user_id])
        .await
        .map_err(ApiError::from)?;

    let profile_picture: Option<String> = match row {
        Some(row) => row.get("profile_picture"),
        None => None,
    };

    Ok(ApiResponse::success(
        profile_picture,
        "User's profile picture retrieved successfully",
        StatusCode::OK,
    ))
}

pub async fn add_or_edit_profile_picture(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
    profile_picture: Json<String>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("UPDATE {} SET profile_picture = $1 WHERE id = $2", TABLE);
    let result = client
        .execute(&stmt, &[&*profile_picture, &user_id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            (),
            "User's profile picture updated successfully",
            StatusCode::CREATED,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found".to_string()));
    }
    Err(ApiError::Custom("Unexpected update count".to_string()))
}

pub async fn delete_profile_picture(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("UPDATE {} SET profile_picture = NULL WHERE id = $1", TABLE);
    let result = client
        .execute(&stmt, &[&user_id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            (),
            "User's profile picture deleted successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found".to_string()));
    }
    Err(ApiError::Custom("Unexpected delete count".to_string()))
}
