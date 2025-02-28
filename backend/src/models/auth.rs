use log::debug;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::utils::{encryption::sha_encrypt_string, jwt::generate_jwt};

use super::user::User;

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub name: Option<String>,
    pub email: String,
    pub password: String,
    pub role: Option<String>, // 'admin' or 'user'
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: User,
    pub token: String,
}

impl AuthResponse {
    pub fn user_to_response(user: User) -> Self {
        debug!("Parsing user to response model");
        let user_id = user.id;
        let role = sha_encrypt_string(user.role.clone()).expect("Error encrypting role");
        let token = generate_jwt(user_id, role).expect("Token error");
        AuthResponse { user, token }
    }

    pub fn row_to_response(row: Row) -> Self {
        debug!("Parsing row to response model");
        let user_id: Uuid = row.get("id");
        let role: String = row.get("role");
        let role = sha_encrypt_string(role).expect("Error encrypting role");
        let token = generate_jwt(user_id, role).expect("Token error");
        AuthResponse {
            user: User::from_row(&row),
            token,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdatePassword {
    pub old_password: String,
    pub new_password: String,
}