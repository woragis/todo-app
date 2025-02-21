use std::sync::Arc;

use axum::{routing::get, Router};
use tokio::sync::Mutex;
use tokio_postgres::Client;

use crate::handlers::todo::{create_todo, delete_todo, get_todo, get_todos, update_todo};

pub fn todo_routes() -> Router<Arc<Mutex<Client>>> {
    Router::new()
        .route("/", get(get_todos).post(create_todo))
        .route("/{id}", get(get_todo).put(update_todo).delete(delete_todo))
}
