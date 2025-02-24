use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::utils::jwt::generate_jwt;

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
        let user_id = user.id;
        let token = generate_jwt(user_id).expect("Token error");
        AuthResponse { user, token }
    }

    pub fn row_to_response(row: Row) -> Self {
        let user_id: Uuid = row.get("id");
        let token = generate_jwt(user_id).expect("Token error");
        AuthResponse {
            user: User::from_row(&row),
            token,
        }
    }
}
