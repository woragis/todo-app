use actix_web::{
    web::{delete, get, post, put, scope},
    Scope,
};

use crate::handlers::admin::{create_user, delete_user, get_user, get_users, update_user};

pub fn user_routes() -> Scope {
    scope("/admin/users")
        .route("/", get().to(get_users))
        .route("/", post().to(create_user))
        .route("/{id}", get().to(get_user))
        .route("/{id}", put().to(update_user))
        .route("/{id}", delete().to(delete_user))
}
