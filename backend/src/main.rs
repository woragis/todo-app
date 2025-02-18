mod database;
mod handlers;
mod models;
mod routes;
mod utils;

use axum::Router;
use database::db::connect;
use routes::{auth::auth_routes, profile::profile_routes, todo::todo_routes, user::user_routes};
use tower_http::cors::{Any, CorsLayer};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};

static HOST: &str = "0.0.0.0:8080";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let pool = connect().await.expect("Error in database connection");
    let client = Arc::new(Mutex::new(pool));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .nest("/auth", auth_routes())
        .nest("/profile", profile_routes())
        .nest("/users", user_routes())
        .nest("/todos", todo_routes())
        .with_state(client)
        .layer(cors);

    let listener = TcpListener::bind(HOST).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    println!("Server running on {}", HOST)
}
