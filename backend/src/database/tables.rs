use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_postgres::{Client, Error};

pub async fn create_tables(client: &Arc<Mutex<Client>>) -> Result<(), Error> {
    const USERS_TABLE: &str = "users";
    const TODOS_TABLE: &str = "todos";

    let create_users_table = format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    );
    ",
        USERS_TABLE
    );

    let create_todos_table = format!(
        "
    CREATE TABLE IF NOT EXISTS {} (
        id UUID PRIMARY KEY,
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
