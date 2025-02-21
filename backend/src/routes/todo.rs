use actix_web::{web::{delete, get, post, put, scope}, Scope};

use crate::handlers::todo::{create_todo, delete_todo, get_todo, get_todos, update_todo};

pub fn todo_routes() -> Scope {
    scope("/todos")
        .route("/", get().to(get_todos))
        .route("/", post().to(create_todo))
        .route("/{id}", get().to(get_todo))
        .route("/{id}", put().to(update_todo))
        .route("/{id}", delete().to(delete_todo))
}
