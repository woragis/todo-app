mod database;
mod handlers;
mod models;
mod routes;
mod utils;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{http::header::{AUTHORIZATION, CONTENT_TYPE}, web::Data, App, HttpServer};
use database::{db::connect, tables::create_tables};
use routes::{auth::auth_routes, profile::profile_routes, todo::todo_routes, user::user_routes};
use tokio::sync::Mutex;

static HOST: &str = "0.0.0.0";
static PORT: u16 = 8080;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();

    let client = connect().await.expect("Error connecting to client");
    let client = Arc::from(Mutex::from(client));

    create_tables(&client).await.ok();

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(client.clone()))
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allowed_headers(vec![AUTHORIZATION, CONTENT_TYPE])
                    .max_age(3600)
            )
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
