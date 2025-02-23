use actix_web::{
    web::{post, scope},
    Scope,
};

use crate::handlers::auth::{login, register};

pub fn auth_routes() -> Scope {
    scope("/auth")
        .route("/login", post().to(login))
        .route("/register", post().to(register))
}
