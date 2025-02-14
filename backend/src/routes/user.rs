use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use tokio::sync::Mutex;
use tokio_postgres::Client;

use crate::handlers::user::{create_user, delete_user, get_user, get_users, update_user};

pub fn user_routes() -> Router<Arc<Mutex<Client>>> {
    Router::new()
        .route("/", post(create_user).get(get_users))
        .route("/{id}", get(get_user).put(update_user).delete(delete_user))
}
