use std::{str::FromStr, sync::Arc};

use crate::{
    models::todo::{CreateTodo, Todo, UpdateTodo},
    utils::{
        jwt::{extract_token, validate_jwt},
        response::{ApiError, ApiResponse},
    },
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::{headers::{authorization::Bearer, Authorization}, TypedHeader};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "todos";
static FIELDS: &str = "title, description, completed, author_id";
static UPDATE_FIELDS: &str = "title = $1, description = $2, completed = $3, author_id = $4";
static FIELDS_INPUT: &str = "$1, $2, $3, $4";

/// **Create Todo**
pub async fn create_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Json(payload): Json<CreateTodo>,
    // TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    // Extract token, returning an error if extraction fails
    // let token = extract_token(&headers).map_err(ApiError::from)?;
    // println!("authorization header: '{}'", authorization.token());

    // Extract token claims, returning an error if extraction fails
    // let claims = validate_jwt(&token).map_err(ApiError::from)?;

    // let user_id = claims.sub;
    let user_id = "oi".to_owned();

    let stmt = format!(
        "INSERT INTO {} ({}) VALUES ({}) RETURNING *",
        TABLE, FIELDS, FIELDS_INPUT
    );

    let row = client
        .query_one(
            &stmt,
            &[&payload.title, &payload.description, &false, &user_id],
        )
        .await
        .map_err(ApiError::from)?;

    let todo = Todo::from_row(&row);
    Ok(ApiResponse::success(
        todo,
        "Todo created successfully",
        StatusCode::CREATED,
    ))
}

/// **Read Todo**
pub async fn get_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    // Extract token, returning an error if extraction fails
    // let token = extract_token(&headers).map_err(ApiError::from)?;
    println!("authorization header: '{}'", authorization.token());

    // Extract token claims, returning an error if extraction fails
    // let claims = validate_jwt(&token).map_err(ApiError::from)?;

    let user_id = "oi".to_owned();

    let stmt = format!("SELECT * FROM {} WHERE id = $1 AND author_id = $2", TABLE);
    let row = client
        .query_one(&stmt, &[&id, &user_id])
        .await
        .map_err(ApiError::from)?;

    let todo = Todo::from_row(&row);
    Ok(ApiResponse::success(
        todo,
        "Todo retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Read Todos**
pub async fn get_todos(
    State(db): State<Arc<Mutex<Client>>>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;


    // // Extract token, returning an error if extraction fails
    // let token = extract_token(&headers).map_err(ApiError::from)?;
    println!("authorization header: '{}'", authorization.token());

    // // Extract token claims, returning an error if extraction fails
    // let claims = validate_jwt(&token).map_err(ApiError::from)?;

    let user_id = "oi".to_owned();

    let stmt = format!("SELECT * FROM {} WHERE author_id = $1", TABLE);
    let rows = client
        .query(&stmt, &[&user_id])
        .await
        .map_err(ApiError::from)?;

    let todos: Vec<Todo> = rows.iter().map(|row| Todo::from_row(row)).collect();
    Ok(ApiResponse::success(
        todos,
        "Todos retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Update Todo**
pub async fn update_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateTodo>,
    // TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    // // Extract token, returning an error if extraction fails
    // let token = extract_token(&headers).map_err(ApiError::from)?;

    // // Extract token claims, returning an error if extraction fails
    // let claims = validate_jwt(&token).map_err(ApiError::from)?;

    let user_id = "oi".to_owned();

    let stmt = format!(
        "UPDATE {} SET {} WHERE id = $5 AND author_id = $4",
        TABLE, UPDATE_FIELDS
    );
    let result = client
        .execute(
            &stmt,
            &[
                &payload.title,
                &payload.description,
                &payload.completed,
                &user_id,
                &id,
            ],
        )
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        let updated_todo = Todo {
            id,
            title: payload.title,
            description: payload.description,
            completed: payload.completed,
            author_id: Uuid::from_str(&user_id).map_err(ApiError::from)?,
        };
        return Ok(ApiResponse::success(
            updated_todo,
            "Todo updated successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("Todo not found on update".to_string()));
    }

    Err(ApiError::Custom("Unexpected update count".to_string()))
}

/// **Delete Todo**
pub async fn delete_todo(
    State(db): State<Arc<Mutex<Client>>>,
    Path(id): Path<Uuid>,
    TypedHeader(authorization): TypedHeader<Authorization<Bearer>>,
) -> Result<impl IntoResponse, ApiError> {
    let client = db.lock().await;

    // Extract token, returning an error if extraction fails
    // let token = extract_token(&headers).map_err(ApiError::from)?;

    // Extract token claims, returning an error if extraction fails
    // let claims = validate_jwt(&token).map_err(ApiError::from)?;

    // let user_id = claims.sub;
    let user_id = "oi".to_owned();

    let stmt = format!("DELETE FROM {} WHERE id = $1 AND author_id = $2", TABLE);
    let result = client
        .execute(&stmt, &[&id, &user_id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        return Ok(ApiResponse::success(
            id.to_string(),
            "Todo deleted successfully",
            StatusCode::OK,
        ));
    } else if result == 0 {
        return Err(ApiError::Custom("Todo not found".to_string()));
    }

    Err(ApiError::Custom("Unexpected delete count".to_string()))
}
