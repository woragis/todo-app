use std::time::Duration;

use crate::models::rate_limiter::RateLimiter;

pub fn rate_limiter() -> RateLimiter {
    RateLimiter::new(100, Duration::from_secs(60))
}
