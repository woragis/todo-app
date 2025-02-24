use std::env;

use deadpool_redis::{Config, Pool};

pub fn pool() -> Pool {
    let redis_url = env::var("REDIS_URL").expect("Error fetching redis url");
    println!("Redis url: {}", redis_url);

    let redis_config = Config::from_url(redis_url);
    let redis_pool = redis_config
        .create_pool(None)
        .expect("Failed to create redis pool");
    redis_pool
}
