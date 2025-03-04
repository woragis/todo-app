use std::sync::Arc;

use log::debug;
use tokio::sync::Mutex;
use tokio_postgres::{Client, Error};

/// Table names for the database.
pub static USERS_TABLE: &str = "users";
pub static TODOS_TABLE: &str = "todos";

/// Creates necessary database tables if they do not exist.
///
/// # Parameters
/// - `client`: A shared and synchronized PostgreSQL client.
///
/// # Returns
/// A `Result` indicating success or failure in creating the tables.
///
/// # Errors
/// Returns an `Error` if any of the table creation queries fail.
pub async fn create_tables(client: &Arc<Mutex<Client>>) -> Result<(), Error> {
    // Log the table creation process.
    debug!("Creating tables: '{}', '{}'", USERS_TABLE, TODOS_TABLE);

    // Ensure the pgcrypto extension is available for UUID generation.
    let extension = "CREATE EXTENSION IF NOT EXISTS pgcrypto;";

    // SQL statement for creating the users table.
    let create_users_table = format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        email_hash CHAR(128) NOT NULL UNIQUE,
        email_encrypt TEXT NOT NULL,
        nonce VARCHAR(24) NOT NULL,
        password TEXT NOT NULL,
        role VARCHAR(5) NOT NULL CHECK (role IN ('admin', 'user')) DEFAULT 'user',
        profile_picture TEXT NULL
    );
    ",
        USERS_TABLE
    );

    // SQL statement for creating the todos table.
    let create_todos_table = format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        description TEXT,
        completed BOOLEAN NOT NULL DEFAULT false,
        user_id UUID NOT NULL,
        FOREIGN KEY (user_id) REFERENCES {}(id) ON DELETE CASCADE
    );
    ",
        TODOS_TABLE, USERS_TABLE
    );

    // Lock the database client to execute queries sequentially.
    let client = client.lock().await;

    // Execute the extension and table creation queries.
    client
        .batch_execute(&extension)
        .await
        .expect("Could not pgcrypto create extension");
    client
        .batch_execute(&create_users_table)
        .await
        .expect("Could not create users table");
    client
        .batch_execute(&create_todos_table)
        .await
        .expect("Could not create todos table");

    Ok(())
}
