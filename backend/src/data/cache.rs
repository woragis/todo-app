use std::env;

use deadpool_redis::{redis::RedisError, Config, Pool};
use log::debug;

/// Creates a Redis connection pool.
///
/// # Returns
/// A `Result` containing the Redis connection pool or an error if pool creation fails.
///
/// # Errors
/// Returns a `RedisError` if the Redis pool cannot be created.
pub fn pool() -> Result<Pool, RedisError> {
    // Fetch the Redis URL from environment variables.
    let redis_url = env::var("REDIS_URL").expect("Error fetching redis url");

    // Log the Redis URL for debugging purposes (this maybe sensitive data).
    debug!("Redis url found: {}", redis_url);

    // Create a Redis configuration from the URL.
    let redis_config = Config::from_url(redis_url);

    // Attempt to create a Redis connection pool.
    let redis_pool = redis_config
        .create_pool(None)
        .expect("Failed to create redis pool");

    Ok(redis_pool)
}
