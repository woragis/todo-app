use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Todo {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub completed: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateTodo {
    pub title: String,
    pub description: String,
}

impl Todo {
    pub fn from_row(row: &Row) -> Self {
        Todo {
            id: row.get("id"),
            title: row.get("name"),
            description: row.get("email"),
            completed: row.get("password"),
        }
    }
}
