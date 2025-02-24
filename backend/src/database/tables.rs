use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_postgres::{Client, Error};

pub async fn create_tables(client: &Arc<Mutex<Client>>) -> Result<(), Error> {
    const USERS_TABLE: &str = "users";
    const TODOS_TABLE: &str = "todos";

    let extension = "CREATE EXTENSION IF NOT EXISTS pgcrypto;";

    let create_users_table = format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(100) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password TEXT NOT NULL,
        role VARCHAR(5) NOT NULL CHECK (role IN ('admin', 'user')) DEFAULT 'user',
        profile_picture TEXT NULL
    );
    ",
        USERS_TABLE
    );

    let create_todos_table = format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        title TEXT NOT NULL,
        description TEXT,
        completed BOOLEAN NOT NULL DEFAULT false,
        author_id UUID NOT NULL,
        FOREIGN KEY (author_id) REFERENCES {}(id) ON DELETE CASCADE
    );
    ",
        TODOS_TABLE, USERS_TABLE
    );

    let client = client.lock().await;
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

    println!("Tables created successfully");

    Ok(())
}
