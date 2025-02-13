mod database;
mod handlers;
mod models;

use axum::{routing::{get, post, }, Router};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};
use database::db::connect;
use handlers::user::{create_user, get_user, get_users, update_user, delete_user};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let pool = connect().await.expect("Error in database connection");
    let client = Arc::new(Mutex::new(pool));

    let app = Router::new()
        .route("/users", post(create_user).get(get_users))
        .route("/users/:id", get(get_user).put(update_user).delete(delete_user))
        .with_state(client);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("Server running on {}", addr);
    
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
