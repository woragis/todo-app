use std::env;

use log::debug;
use tokio_postgres::{Client, Error, NoTls};

pub async fn connect() -> Result<Client, Error> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    debug!("Database url found: {}", database_url);

    let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Database connection error: {}", e);
        }
    });

    Ok(client)
}
