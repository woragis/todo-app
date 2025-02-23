use std::{str::FromStr, sync::Arc};

use crate::{
    models::{response::{ApiError, ApiResponse}, todo::{CreateTodo, Todo, UpdateTodo}},
    utils::jwt::{extract_token, validate_jwt},
};
use actix_web::{http::StatusCode, web::{Data, Json, Path}, HttpRequest, HttpResponse};
use deadpool_redis::Pool;
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;

static TABLE: &str = "todos";
static FIELDS: &str = "title, description, completed, author_id";
static UPDATE_FIELDS: &str = "title = $1, description = $2, completed = $3, author_id = $4";
static FIELDS_INPUT: &str = "$1, $2, $3, $4";

/// **Create Todo**
pub async fn create_todo(
    client: Data<Arc<Mutex<Client>>>,
    redis_pool: Data<Arc<Pool>>,
    payload: Json<CreateTodo>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
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

    // ✅ Store new todo in Redis
    todo.to_redis(&redis_pool, user_id).await?;

    Ok(ApiResponse::success(
        todo,
        "Todo created successfully",
        StatusCode::CREATED,
    ))
}


/// **Read Todo**
pub async fn get_todo(
    client: Data<Arc<Mutex<Client>>>,
    redis_pool: Data<Arc<Pool>>,
    request: HttpRequest,
    id: Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let id = *id;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    if let Some(todo) = Todo::from_redis(&redis_pool, id, user_id).await? {
        return Ok(ApiResponse::success(todo, "Todo retrieved from cache", StatusCode::OK));
    }

    let client = client.lock().await;
    let stmt = format!("SELECT * FROM {} WHERE id = $1 AND author_id = $2", TABLE);
    let row = client
        .query_one(&stmt, &[&id, &user_id])
        .await
        .map_err(ApiError::from)?;

    let todo = Todo::from_row(&row);

    todo.to_redis(&redis_pool, user_id).await?;

    Ok(ApiResponse::success(
        todo,
        "Todo retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Read Todos**
pub async fn get_todos(
    client: Data<Arc<Mutex<Client>>>,
    redis_pool: Data<Arc<Pool>>,
    request: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("SELECT * FROM {} WHERE author_id = $1", TABLE);
    let rows = client
        .query(&stmt, &[&user_id])
        .await
        .map_err(ApiError::from)?;

    let mut todos = Vec::new();

    for row in rows {
        let todo = Todo::from_row(&row);
        todo.to_redis(&redis_pool, user_id).await?;
        todos.push(todo);
    }

    Ok(ApiResponse::success(
        todos,
        "Todos retrieved successfully",
        StatusCode::OK,
    ))
}

/// **Update Todo**
pub async fn update_todo(
    client: Data<Arc<Mutex<Client>>>,
    redis_pool: Data<Arc<Pool>>,
    payload: Json<UpdateTodo>,
    request: HttpRequest,
    id: Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
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
                &*id,
            ],
        )
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        let updated_todo = Todo {
            id: *id,
            title: payload.title.to_owned(),
            description: payload.description.to_owned(),
            completed: payload.completed,
            author_id: user_id,
        };

        // ✅ Remove old cache
        Todo::delete_from_redis(&redis_pool, *id, user_id).await?;

        // ✅ Store updated todo in cache
        updated_todo.to_redis(&redis_pool, user_id).await?;

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
    client: Data<Arc<Mutex<Client>>>,
    redis_pool: Data<Arc<Pool>>,
    request: HttpRequest,
    id: Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let token = extract_token(&request.headers()).map_err(ApiError::from)?;
    let claims = validate_jwt(&token).map_err(ApiError::from)?;
    let user_id = Uuid::from_str(&claims.sub).map_err(ApiError::from)?;

    let client = client.lock().await;
    let stmt = format!("DELETE FROM {} WHERE id = $1 AND author_id = $2", TABLE);
    let result = client
        .execute(&stmt, &[&*id, &user_id])
        .await
        .map_err(ApiError::from)?;

    if result == 1 {
        // ✅ Remove from cache
        Todo::delete_from_redis(&redis_pool, *id, user_id).await?;

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
