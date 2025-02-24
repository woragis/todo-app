use core::panic;
use std::sync::Arc;

use crate::models::{
    response::{ApiError, ApiResponse},
    user::{CreateUser, UpdateUser, User},
};
use actix_web::{
    http::StatusCode,
    web::{self, Data, Json, Path},
    HttpResponse, Responder,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "users";
static FIELDS: &str = "name, email, password";
static UPDATE_FIELDS: &str = "name = $1, email = $2, password = $3";
static FIELDS_INPUT: &str = "$1, $2, $3";

pub async fn create_user(
    client: Data<Arc<Mutex<Client>>>,
    payload: web::Json<CreateUser>,
) -> Result<HttpResponse, ApiError> {
    let client = client.lock().await;

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );

    let row = client
        .query_one(&stmt, &[&payload.name, &payload.email, &payload.password])
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
    user_id: Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let client = client.lock().await;

    let user_id = user_id.to_string();

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

/// **Read Users**
pub async fn get_users(client: web::Data<Arc<Mutex<Client>>>) -> Result<HttpResponse, ApiError> {
    let client = client.lock().await;

    let stmt = format!("SELECT * FROM {}", TABLE);
    let rows = client.query(&stmt, &[]).await.map_err(ApiError::from)?;

    let users: Vec<User> = rows
        .iter()
        .map(|row| User::from_row(row))
        .collect();

    Ok(ApiResponse::success(
        users,
        "Users retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Update User**
pub async fn update_user(
    client: Data<Arc<Mutex<Client>>>,
    user_id: Path<Uuid>,
    payload: Json<UpdateUser>,
) -> impl Responder {
    let client = client.lock().await;

    let user_id = user_id.to_string();

    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &payload.password, &user_id],
        )
        .await
        .map_err(ApiError::from);

    match result {
        Ok(1) => ApiResponse::success(
            user_id.to_string(),
            "User updated successfully",
            StatusCode::OK,
        ),
        _ => panic!("Error in update user"),
    }
}
/// **Delete User**
pub async fn delete_user(client: Data<Arc<Mutex<Client>>>, user_id: Path<Uuid>) -> impl Responder {
    let client = client.lock().await;

    let user_id = user_id.to_string();

    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client
        .execute(&stmt, &[&user_id])
        .await
        .map_err(ApiError::from);

    match result {
        Ok(1) => ApiResponse::success(
            user_id.to_string(),
            "User deleted successfully",
            StatusCode::OK,
        ),
        _ => panic!("Error in update user"),
    }
}
