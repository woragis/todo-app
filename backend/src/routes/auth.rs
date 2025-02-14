use std::sync::Arc;

use axum::{routing::post, Router};
use tokio::sync::Mutex;
use tokio_postgres::Client;

use crate::handlers::auth::{login, register};

pub fn auth_routes() -> Router<Arc<Mutex<Client>>> {
    Router::new()
        .route("/login", post(login))
        .route("/register", post(register))
}
