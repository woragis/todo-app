use std::{str::FromStr, sync::Arc};

use crate::{
    models::{
        auth::UpdatePassword, response::{ApiError, ApiResponse}, user::{UpdateProfile, User}
    },
    utils::{bcrypt::hash_password, jwt::{extract_token, validate_jwt}, regex::{regex_email, regex_password}},
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
        .execute(
            &stmt,
            &[&payload.name, &payload.email, &user_id],
        )
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
    payload: Json<UpdatePassword>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    // let is_equal = compare_password(&payload.oldpassword, &user.password).map_err(ApiError::from)?;
    // match is_equal {
    //     false => Err(ApiError::Auth(AuthError::PasswordWrong)),
    //     true => {
    //         // generate token
    //         Ok(ApiResponse::success(
    //             AuthResponse::user_to_response(user),
    //             "Successfully logged in",
    //             StatusCode::OK,
    //         ))
    //     }
    // }

    regex_password(&payload.new_password)?;
    let hashed_password = hash_password(&payload.new_password).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("UPDATE {} SET password = $1 WHERE id = $2", TABLE);
    let result = client
        .execute(
            &stmt,
            &[&hashed_password, &user_id],
        )
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
