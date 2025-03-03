use std::env;

use log::debug;
use tokio_postgres::{Client, Error, NoTls};

/// Establishes a connection to the PostgreSQL database.
///
/// # Returns
/// A `Result` containing the `Client` for executing queries or an error if the connection fails.
///
/// # Errors
/// Returns an `Error` if the database connection cannot be established.
pub async fn connect() -> Result<Client, Error> {
    // Fetch the database URL from environment variables.
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Log the database URL for debugging purposes (consider masking sensitive data).
    debug!("Database url found: {}", database_url);

    // Attempt to connect to the PostgreSQL database.
    let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;

    // Spawn a separate task to manage the connection and handle potential errors.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            log::error!("Database connection error: {}", e);
        }
    });

    Ok(client)
}
