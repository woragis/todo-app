use std::sync::Arc;

use crate::{
    models::{auth::{AuthRequest, AuthResponse}, user::User},
    utils::{jwt::AuthError, response::{ApiError, ApiResponse}},
};
use actix_web::{http::StatusCode, web::{Data, Json}, HttpResponse};
use tokio::sync::Mutex;
use tokio_postgres::Client;

static TABLE: &str = "users";
static FIELDS: &str = "name, email, password";
static FIELDS_INPUT: &str = "$1, $2, $3";

/// **Login User**
pub async fn login(
    client: Data<Arc<Mutex<Client>>>,
    payload: Json<AuthRequest>,
) -> Result<HttpResponse, ApiError> {
    println!("Login request received for email: {}", payload.email);

    match test_email(&client, payload.email.clone()).await {
        Ok(Some(user)) => {
            // test if password is right
            // with bcrypt
            match payload.password == user.password {
                false => Err(ApiError::Auth(AuthError::PasswordWrong)),
                true => {
                    // generate token
                    Ok(
                        ApiResponse::success(
                            AuthResponse::user_to_response(user),
                            "Successfully logged in",
                            StatusCode::OK
                        )
                    )
                },
            }
        },
        Ok(None) => return Err(ApiError::Auth(AuthError::EmailWrong)),
        Err(err) => return Err(err)
    }

    // if !email_exists {
    //     return Ok(ApiResponse::success(
    //         (), "email not found", StatusCode::BAD_REQUEST
    //     ));
    // }

    // let client = client.lock().await;

    // let stmt = format!("SELECT * FROM {} WHERE email = $1", TABLE);
    // let row = client
    //     .query_one(&stmt, &[&payload.email])
    //     .await
    //     .map_err(ApiError::from)?;

    // println!("User found in database");

    // let response = AuthResponse::row_to_response(row);
    // Ok(ApiResponse::success(
    //     response,
    //     "User logged in successfully",
    //     StatusCode::OK,
    // ))
}

/// **Register User**
pub async fn register(
    client: Data<Arc<Mutex<Client>>>,
    payload: Json<AuthRequest>,
) -> Result<HttpResponse, ApiError> {
    println!("Register request received for email: {}", payload.email);

    match test_email(&client, payload.email.clone()).await {
        Ok(None) => {
            // test if password is right
            // with bcrypt
            let client = client.lock().await;

            let stmt = format!(
                "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
                TABLE, FIELDS, FIELDS_INPUT
            );

            let row = client
                .query_one(&stmt, &[&payload.name, &payload.email, &payload.password])
                .await
                .map_err(ApiError::from)?;

            let response = AuthResponse::row_to_response(row);
            Ok(ApiResponse::success(
                response,
                "User registered successfully",
                StatusCode::CREATED,
            ))
            // match payload.password == user.password {
            //     false => Err(ApiError::Auth(AuthError::PasswordWrong)),
            //     true => {
            //         // generate token
            //         Ok(
            //             ApiResponse::success(
            //                 AuthResponse::user_to_response(user),
            //                 "Successfully logged in",
            //                 StatusCode::OK
            //             )
            //         )
            //     },
            // }
        },
        Ok(Some(_)) => {
            Err(ApiError::Auth(AuthError::EmailTaken))
        },
        Err(err) => return Err(err)
    }


    // if email_exists {
    //     return Ok(ApiResponse::success(
    //         (), "email already taken", StatusCode::BAD_REQUEST
    //     ));
    // }

    // let client = client.lock().await;

    // let stmt = format!(
    //     "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
    //     TABLE, FIELDS, FIELDS_INPUT
    // );
    // let row = client
    //     .query_one(&stmt, &[&payload.name, &payload.email, &payload.password])
    //     .await
    //     .map_err(ApiError::from)?;

    // println!("User registered successfully");

    // let response = AuthResponse::row_to_response(row);
    // Ok(ApiResponse::success(
    //     response,
    //     "User registered successfully",
    //     StatusCode::CREATED,
    // ))
}

async fn test_email(client: &Arc<Mutex<Client>>, email: String) -> Result<Option<User>, ApiError> {
    let client = client.lock().await;

    let stmt = format!("SELECT * FROM {} WHERE email = $1", TABLE);

    match client.query_opt(&stmt, &[&email]).await {
        Ok(Some(row)) => Ok(Some(User::from_row(&row))),
        Ok(None) => Ok(None),
        Err(_) => Err(ApiError::Auth(AuthError::InvalidHeader)),
    }
}