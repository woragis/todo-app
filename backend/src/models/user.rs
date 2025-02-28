use log::debug;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email_hash: String,
    pub email_encrypt: String,
    pub nonce: String,
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
pub struct UpdateProfile {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUser {
    pub name: String,
    pub email: String,
    pub password: String,
}


impl User {
    pub fn from_row(row: &Row) -> Self {
        debug!("Parsing row to user model");
        User {
            id: row.get("id"),
            name: row.get("name"),
            // email_hash: row.get("email_hash"),
            email_hash: String::new(),
            // email_encrypt: row.get("email_encrypt"),
            email_encrypt: String::new(),
            // nonce: row.get("nonce"),
            nonce: String::new(),
            // password: row.get("password"),
            password: String::new(),
            role: row.get("role"),
            profile_picture: row.get("profile_picture"),
        }
    }
}
