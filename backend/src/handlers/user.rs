use axum::{Json, extract::Path, http::StatusCode};
use uuid::Uuid;
use crate::{database::db::connect, models::user::{CreateUser, User}};

/// **Create User**
pub async fn create_user(Json(payload): Json<CreateUser>) -> Result<StatusCode, StatusCode> {
    let client = connect().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result = client
        .execute(
            "INSERT INTO users (name, email) VALUES ($1, $2)",
            &[&payload.name, &payload.email],
        )
        .await;

    match result {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// **Read User**
pub async fn get_user(Path(id): Path<Uuid>) -> Result<Json<User>, StatusCode> {
    let client = connect().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let row = client.query_one("SELECT * FROM users WHERE id = $1;", &[&id]).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let user: User = User::from_row(&row);

    Ok(Json(user))
}

/// **Read Users**
pub async fn get_users() -> Result<Json<Vec<User>>, StatusCode> {
    let client = connect().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let rows = client.query("SELECT id, name, email FROM users", &[]).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let users: Vec<User> = rows.iter().map(|row| User::from_row(row)).collect();

    Ok(Json(users))
}

/// **Update User**
pub async fn update_user(Path(id): Path<Uuid>, Json(payload): Json<CreateUser>) -> Result<StatusCode, StatusCode> {
    let client = connect().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result = client
        .execute(
            "UPDATE users SET name = $1, email = $2 WHERE id = $3",
            &[&payload.name, &payload.email, &id],
        )
        .await;

    match result {
        Ok(1) => Ok(StatusCode::OK),
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// **Delete User**
pub async fn delete_user(Path(id): Path<Uuid>) -> Result<StatusCode, StatusCode> {
    let client = connect().await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result = client.execute("DELETE FROM users WHERE id = $1", &[&id]).await;

    match result {
        Ok(1) => Ok(StatusCode::OK),
        Ok(_) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
