use std::env;

use tokio_postgres::{Client, Error, NoTls};

pub async fn connect() -> Result<Client, Error> {
    println!("Initializing Database connection.....");
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    println!(
        "Seems like the DATABASE_URL was found and set: {}",
        database_url
    );

    println!("Connecting Database.....");
    let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;
    println!("Successfully connected to Database!");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("Database connection error: {}", e);
        }
    });

    Ok(client)
}
