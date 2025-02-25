mod data;
mod handlers;
mod middlewares;
mod models;
mod routes;
mod utils;

use std::{env, process::exit, sync::Arc};

use actix_cors::Cors;
use actix_web::{
    http::header::{AUTHORIZATION, CONTENT_TYPE},
    web::{get, Data},
    App, HttpServer,
};
use chrono::Local;
use data::{cache::pool, db::connect, tables::create_tables};
use fern::Dispatch;
use log::{error, info, LevelFilter};
use middlewares::rate_limiter::rate_limiter;
use models::rate_limiter::index;
use routes::{auth::auth_routes, profile::profile_routes, todo::todo_routes, user::user_routes};
use tokio::sync::Mutex;

static HOST: &str = "0.0.0.0";
static PORT: u16 = 8080;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let level_filter = match log_level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };

    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                message
            ))
        })
        .level(level_filter)
        .chain(std::io::stdout())
        .chain(fern::log_file("output.log").unwrap())
        .apply()
        .unwrap();

    info!("Application logger initialized");

    dotenvy::dotenv().ok();

    let redis_pool = match pool() {
        Ok(redis_pool) => {
            info!("Redis cache connected");
            Arc::new(redis_pool)
        },
        Err(e) => {
            error!("Error connecting to redis cache: {}", e);
            exit(2);
        }
    };

    let client = match connect().await {
        Ok(client) => {
            info!("Database client connected");
            Arc::new(Mutex::from(client))
        },
        Err(e) => {
            error!("Error connecting to postgres database: {}", e);
            exit(3);
        }
    };

    match create_tables(&client).await {
        Ok(()) => {
            info!("Created tables");
            ()
        },
        Err(e) => {
            error!("Error creating tables: {}", e);
            exit(4);
        },
    }

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
    .unwrap_or_else(|e| {
        error!("Failed to bind address {}:{}: {}", HOST, PORT, e);
        exit(1);
    })
    .run()
    .await
}
