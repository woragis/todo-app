use std::env;

use deadpool_redis::{redis::RedisError, Config, Pool};
use log::debug;

pub fn pool() -> Result<Pool, RedisError> {
    let redis_url = env::var("REDIS_URL").expect("Error fetching redis url");
    debug!("Redis url found: {}", redis_url);

    let redis_config = Config::from_url(redis_url);
    let redis_pool = redis_config
        .create_pool(None)
        .expect("Failed to create redis pool");

    Ok(redis_pool)
}
