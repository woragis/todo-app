use std::{str::FromStr, sync::Arc};

use crate::{
    models::{
        response::{ApiError, ApiResponse},
        user::{UpdateUser, User},
    },
    utils::jwt::{extract_token, validate_jwt},
};
use actix_web::{
    http::StatusCode,
    web::{Data, Json},
    HttpRequest, HttpResponse,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "users";
static UPDATE_FIELDS: &str = "name = $1, email = $2, password = $3";

/// **Read User Profile**
pub async fn get_user_profile(
    client: Data<Arc<Mutex<Client>>>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let client = client.lock().await;

    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let id = claims.sub;

    let stmt = format!("SELECT * FROM {} WHERE id = $1", TABLE);
    let row = client
        .query_one(&stmt, &[&id])
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
    payload: Json<UpdateUser>,
) -> Result<HttpResponse, ApiError> {
    let client = client.lock().await;

    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let id = claims.sub;

    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &payload.password, &id],
        )
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        let updated_user = User {
            id: Uuid::from_str(&id).map_err(ApiError::from)?,
            name: payload.name.to_owned(),
            email: payload.email.to_owned(),
            password: payload.password.to_owned(),
        };
        return Ok(ApiResponse::success(
            updated_user,
            "User updated successfully",
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
    let client = client.lock().await;

    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let id = claims.sub;

    let stmt = format!("DELETE FROM {} WHERE id = $1", TABLE);
    let result = client
        .execute(&stmt, &[&id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            id.to_string(),
            "User deleted successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("User not found".to_string()));
    }

    Err(ApiError::Custom("Unexpected delete count".to_string()))
}
