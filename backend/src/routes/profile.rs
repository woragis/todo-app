use std::sync::Arc;

use axum::{routing::get, Router};
use tokio::sync::Mutex;
use tokio_postgres::Client;

use crate::handlers::profile::{delete_user_profile, get_user_profile, update_user_profile};

pub fn profile_routes() -> Router<Arc<Mutex<Client>>> {
    Router::new().route(
        "/",
        get(get_user_profile)
            .put(update_user_profile)
            .delete(delete_user_profile),
    )
}
