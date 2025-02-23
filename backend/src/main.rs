mod database;
mod handlers;
mod middlewares;
mod models;
mod routes;
mod utils;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{
    http::header::{AUTHORIZATION, CONTENT_TYPE},
    web::{get, Data},
    App, HttpServer,
};
use database::{cache::pool, db::connect, tables::create_tables};
use middlewares::rate_limiter::rate_limiter;
use models::rate_limiter::index;
use routes::{auth::auth_routes, profile::profile_routes, todo::todo_routes, user::user_routes};
use tokio::sync::Mutex;

static HOST: &str = "0.0.0.0";
static PORT: u16 = 8080;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let redis_pool = Arc::new(pool());

    let client = connect().await.expect("Error connecting to client");
    let client = Arc::from(Mutex::from(client));

    create_tables(&client).await.ok();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(client.clone()))
            .app_data(Data::new(redis_pool.clone()))
            .app_data(Data::new(rate_limiter()))
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allowed_headers(vec![AUTHORIZATION, CONTENT_TYPE])
                    .max_age(3600),
            )
            .route("/", get().to(index))
            .service(auth_routes())
            .service(profile_routes())
            .service(todo_routes())
            .service(user_routes())
    })
    .bind((HOST, PORT))
    .expect("Could not")
    .run()
    .await
}
