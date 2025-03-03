use core::panic;
use std::sync::Arc;

use crate::{
    models::{
        response::{ApiError, ApiResponse, AuthError},
        user::{CreateUser, UpdateUser, User},
    },
    utils::{
        bcrypt::hash_password,
        encryption::sha_encrypt_string,
        jwt::{extract_token, validate_jwt},
    },
};
use actix_web::{
    http::StatusCode,
    web::{self, Data, Json, Path},
    HttpRequest, HttpResponse,
};
use once_cell::sync::Lazy;
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "users";
static FIELDS: &str = "name, email, password";
static UPDATE_FIELDS: &str = "name = $1, email = $2, password = $3";
static FIELDS_INPUT: &str = "$1, $2, $3";

static ADMIN_ROLE: Lazy<String> =
    Lazy::new(|| sha_encrypt_string("admin".to_string()).expect("msg"));

pub async fn create_user(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
    payload: web::Json<CreateUser>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let role = claims.role;
    match role == ADMIN_ROLE.as_ref() {
        true => (),
        false => return Err(ApiError::Auth(AuthError::AdminsOnly)),
    }

    let hashed_password = hash_password(&payload.password).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );
    let row = client
        .query_one(&stmt, &[&payload.name, &payload.email, &hashed_password])
        .await
        .map_err(ApiError::from)?;

    let user = User::from_row(&row);

    Ok(ApiResponse::success(
        user,
        "User created successfully",
        StatusCode::CREATED,
    ))
}

/// **Read User**
pub async fn get_user(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
    user_id: Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let role = claims.role;
    match role == ADMIN_ROLE.as_ref() {
        true => (),
        false => return Err(ApiError::Auth(AuthError::AdminsOnly)),
    }

    let client = client.lock().await;
    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client
        .query_one(&stmt, &[&*user_id])
        .await
        .map_err(ApiError::from)?;

    let user = User::from_row(&row);

    Ok(ApiResponse::success(
        user,
        "User retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Read Users**
pub async fn get_users(
    client: web::Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let role = claims.role;
    println!("user hashed role: {}", role);
    println!("admin hashed role: {}", ADMIN_ROLE.to_string());
    match role == ADMIN_ROLE.as_ref() {
        true => (),
        false => return Err(ApiError::Auth(AuthError::AdminsOnly)),
    }

    let client = client.lock().await;
    let stmt = format!("SELECT * FROM {}", TABLE);
    let rows = client.query(&stmt, &[]).await.map_err(ApiError::from)?;

    let users: Vec<User> = rows.iter().map(|row| User::from_row(row)).collect();

    Ok(ApiResponse::success(
        users,
        "Users retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Update User**
pub async fn update_user(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
    user_id: Path<Uuid>,
    payload: Json<UpdateUser>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let role = claims.role;
    match role == ADMIN_ROLE.as_ref() {
        true => (),
        false => return Err(ApiError::Auth(AuthError::AdminsOnly)),
    }

    let hashed_password = hash_password(&payload.password).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &hashed_password, &*user_id],
        )
        .await
        .map_err(ApiError::from);

    match result {
        Ok(1) => Ok(ApiResponse::success(
            *user_id,
            "User updated successfully",
            StatusCode::OK,
        )),
        // update response
        _ => panic!("Error in update user"),
    }
}

/// **Delete User**
pub async fn delete_user(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
    user_id: Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let role = claims.role;
    match role == ADMIN_ROLE.as_ref() {
        true => (),
        false => return Err(ApiError::Auth(AuthError::AdminsOnly)),
    }

    let client = client.lock().await;
    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client
        .execute(&stmt, &[&*user_id])
        .await
        .map_err(ApiError::from);

    match result {
        Ok(1) => Ok(ApiResponse::success(
            user_id.to_string(),
            "User deleted successfully",
            StatusCode::OK,
        )),
        // update response
        _ => panic!("Error in delete user"),
    }
}
