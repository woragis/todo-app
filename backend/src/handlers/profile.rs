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
    payload: Json<UpdateUser>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("UPDATE {} SET {} WHERE id = $4", TABLE, UPDATE_FIELDS);
    let result = client
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &payload.password, &user_id],
        )
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        let updated_user = User {
            id: user_id,
            name: payload.name.to_owned(),
            email: payload.email.to_owned(),
            password: payload.password.to_owned(),
            role: String::from("user"),
            profile_picture: Some(String::new()),
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
            "User deleted successfully",
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
