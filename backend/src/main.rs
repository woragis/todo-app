mod database;
mod handlers;
mod models;
mod routes;
mod utils;

use axum::Router;
use database::db::connect;
use routes::{todo::todo_routes, user::user_routes};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};

static HOST: &str = "0.0.0.0:8080";

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let pool = connect().await.expect("Error in database connection");
    let client = Arc::new(Mutex::new(pool));

    let app = Router::new()
        .nest("/users", user_routes())
        .nest("/todos", todo_routes())
        .with_state(client);

    let listener = TcpListener::bind(HOST).await.unwrap();
    axum::serve(listener, app).await.unwrap();
    println!("Server running on {}", HOST)
}
