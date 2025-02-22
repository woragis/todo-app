use actix_web::web::Data;
use actix_web::{HttpRequest, HttpResponse};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::utils::response::ApiError;

#[derive(Clone)]
pub struct RateLimiter {
    // Maps IP addresses to (request count, window start time)
    requests: Arc<Mutex<HashMap<String, (usize, Instant)>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        RateLimiter {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }
    pub fn is_allowed(&self, ip: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now= Instant::now();
        let entry = requests.entry(ip.to_string()).or_insert((0, now));
        // if the window has passed, reset the counter
        if now.duration_since(entry.1) > self.window {
            *entry = (1,now);
            true
        } else {
            if entry.0 < self.max_requests {
                entry.0 += 1;
                true
            } else {
                false
            }
        }
    }
    pub fn check_rate_limit(&self, req: &HttpRequest) -> Result<(), ApiError> {
        if let Some(peer_addr) = req.peer_addr() {
            let ip = peer_addr.ip().to_string();
            if !self.is_allowed(&ip) {
                // return Err(HttpResponse::TooManyRequests().body("Too many requests"));
                return Err(ApiError::TooManyRequests);
            }
        }
        Ok(())
    }
}

pub async fn index(req: HttpRequest, data: Data<RateLimiter>) -> Result<HttpResponse, ApiError> {
    data.check_rate_limit(&req).map_err(ApiError::from)?;
    Ok(HttpResponse::Ok().body("Hello, World!"))
}