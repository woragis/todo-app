use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::utils::jwt::generate_jwt;

use super::user::User;

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: User,
    pub token: String,
}

impl AuthResponse {
    pub fn row_to_response(row: Row) -> Self {
        let user_id: Uuid = row.get("id");
        let token = generate_jwt(&user_id.to_string()).expect("Token error");
        AuthResponse {
            user: User::from_row(&row),
            token,
        }
    }
}
