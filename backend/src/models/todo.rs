use deadpool_redis::{redis::AsyncCommands, Pool};
use log::debug;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::models::response::ApiError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Todo {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub completed: bool,
    pub user_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct CreateTodo {
    pub title: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTodo {
    pub title: String,
    pub description: String,
    pub completed: bool,
}

impl Todo {
    pub fn from_row(row: &Row) -> Self {
        debug!("Parsing row to todo model");
        Todo {
            id: row.get("id"),
            title: row.get("title"),
            description: row.get("description"),
            completed: row.get("completed"),
            user_id: row.get("user_id"),
        }
    }

    pub fn from_str(todo_str: &str) -> Result<Self, serde_json::Error> {
        debug!("Parsing string to todo model");
        serde_json::from_str(todo_str)
    }

    pub fn to_str(&self) -> Result<String, serde_json::Error> {
        debug!("Parsing todo model to string");
        serde_json::to_string(self)
    }

    /// Store the `Todo` in Redis with `todo:<id>:author_id:<user_id>` as the key.
    pub async fn to_redis(&self, redis_pool: &Pool, user_id: Uuid) -> Result<(), ApiError> {
        debug!("Saving todo on redis");
        let mut conn = redis_pool.get().await.map_err(ApiError::from)?;
        let key = format!("todo:{}:author_id:{}", self.id, user_id);

        let value = self.to_str().map_err(ApiError::from)?;

        // cmd("SET").arg(&[&key, &value]);
        conn.set_ex(key, value, 3600).await.map_err(ApiError::from)
    }

    /// Retrieve a `Todo` from Redis by ID.
    pub async fn from_redis(
        redis_pool: &Pool,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Self>, ApiError> {
        debug!("Fetching todo from redis");
        let mut conn = redis_pool.get().await.map_err(ApiError::from)?;
        let key = format!("todo:{}:author_id:{}", id, user_id);
        let result: Option<String> = conn.get(&key).await?;

        if let Some(todo_str) = result {
            let todo = Todo::from_str(&todo_str).map_err(ApiError::from)?;
            Ok(Some(todo))
        } else {
            Ok(None)
        }
    }

    /// **Delete a `Todo` from Redis by ID**
    pub async fn delete_from_redis(
        redis_pool: &Pool,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<(), ApiError> {
        debug!("Deleting todo from redis");
        let mut conn = redis_pool.get().await.map_err(ApiError::from)?;
        let key = format!("todo:{}:author_id:{}", id, user_id);

        // Execute the DEL command to remove the key from Redis
        let _: () = conn.del(&key).await.map_err(ApiError::from)?;

        Ok(())
    }
}
