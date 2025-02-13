use std::sync::Arc;

use axum::{extract::{Path, State}, http::StatusCode, Json};
use tokio::sync::Mutex;
use tokio_postgres::Client;
use uuid::Uuid;
use crate::models::user::{CreateUser, User};

/// **Create User**
pub async fn create_user(State(db): State<Arc<Mutex<Client>>>, Json(payload): Json<CreateUser>) -> Result<StatusCode, StatusCode> {
    let client = db.lock().await;

    let result = client
        .execute(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
            &[&payload.name, &payload.email, &payload.password],
        )
        .await;

    match result {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// **Read User**
pub async fn get_user(State(db): State<Arc<Mutex<Client>>>, Path(id): Path<Uuid>) -> Result<Json<User>, StatusCode> {
    let client = db.lock().await;

    let row = client.query_one("SELECT * FROM users WHERE id = $1", &[&id]).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user: User = User::from_row(&row);

    Ok(Json(user))
}

/// **Read Users**
pub async fn get_users(State(db): State<Arc<Mutex<Client>>>, ) -> Result<Json<Vec<User>>, StatusCode> {
    let client = db.lock().await;
    
    let rows = client.query("SELECT * FROM users", &[]).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let users: Vec<User> = rows.iter().map(|row| User::from_row(row)).collect();

    Ok(Json(users))
}

/// **Update User**
pub async fn update_user(State(db): State<Arc<Mutex<Client>>>, Path(id): Path<Uuid>, Json(payload): Json<CreateUser>) -> Result<StatusCode, StatusCode> {
    let client = db.lock().await;

    let result = client
        .execute(
            "UPDATE users SET name = $1, email = $2, password = $3 WHERE id = $4",
            &[&payload.name, &payload.email, &payload.password, &id],
        )
        .await;

    match result {
        Ok(1) => Ok(StatusCode::OK),
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// **Delete User**
pub async fn delete_user(State(db): State<Arc<Mutex<Client>>>, Path(id): Path<Uuid>) -> Result<StatusCode, StatusCode> {
    let client = db.lock().await;

    let result = client.execute("DELETE FROM users WHERE id = $1", &[&id]).await;

    match result {
        Ok(1) => Ok(StatusCode::OK),
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
