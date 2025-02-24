use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: String, // 'admin' or 'user'
    pub profile_picture: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub name: String,
    pub email: String,
    pub password: String,
}

impl User {
    pub fn from_row(row: &Row) -> Self {
        User {
            id: row.get("id"),
            name: row.get("name"),
            email: row.get("email"),
            password: row.get("password"),
            role: row.get("role"),
            profile_picture: row.get("profile_picture"),
        }
    }
}
