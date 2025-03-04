use log::debug;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::utils::{encryption::sha_encrypt_string, jwt::generate_jwt};

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
            email_hash: row.get("email_hash"),
            // email_hash: String::new(),
            email_encrypt: row.get("email_encrypt"),
            // email_encrypt: String::new(),
            nonce: row.get("nonce"),
            // nonce: String::new(),
            password: row.get("password"),
            // password: String::new(),
            role: row.get("role"),
            profile_picture: row.get("profile_picture"),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UserAuthRequest {
    pub name: Option<String>,
    pub email: String,
    pub password: String,
    pub role: Option<String>, // 'admin' or 'user'
}

#[derive(Debug, Serialize)]
pub struct UserAuthResponse {
    pub user: User,
    pub token: String,
}

impl UserAuthResponse {
    pub fn user_to_response(user: User) -> Self {
        debug!("Parsing user to response model");
        let user_id = user.id;
        let role = sha_encrypt_string(user.role.clone()).expect("Error encrypting role");
        let token = generate_jwt(user_id, role).expect("Token error");
        UserAuthResponse { user, token }
    }

    pub fn row_to_response(row: Row) -> Self {
        debug!("Parsing row to response model");
        let user_id: Uuid = row.get("id");
        let role: String = row.get("role");
        let role = sha_encrypt_string(role).expect("Error encrypting role");
        let token = generate_jwt(user_id, role).expect("Token error");
        UserAuthResponse {
            user: User::from_row(&row),
            token,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UserUpdatePassword {
    pub old_password: String,
    pub new_password: String,
}
