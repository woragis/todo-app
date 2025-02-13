mod database;
mod handlers;
mod models;

use axum::{
    routing::{get, post},
    Router,
};
use database::db::connect;
use handlers::user::{create_user, delete_user, get_user, get_users, update_user};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};

static HOST: &str = "0.0.0.0:8080";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let pool = connect().await.expect("Error in database connection");
    let client = Arc::new(Mutex::new(pool));

    let app = Router::new()
        .route("/users", post(create_user).get(get_users))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .with_state(client);

    let listener = TcpListener::bind(HOST).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    println!("Server running on {}", HOST)
}
