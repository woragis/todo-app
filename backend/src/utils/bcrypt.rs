use bcrypt::{hash, verify};
use log::{debug, error};

use crate::models::response::ApiError;

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    match hash(password, 12) {
        Ok(hash) => {
            debug!("Hashed password: {} to {}", password, hash);
            Ok(hash)
        }
        Err(e) => {
            error!("Bcrypt error: {}", e);
            Err(ApiError::Bcrypt(e))
        }
    }
}

pub fn compare_password(password: &str, hash: &str) -> Result<bool, ApiError> {
    match verify(password, hash) {
        Ok(is_equal) => {
            debug!("comparing password... is equal?: {}", is_equal);
            Ok(is_equal)
        }
        Err(e) => {
            debug!("comparing passwords: '{}' and '{}'\nError: {}", password, hash, e);
            error!("Bcrypt error: {}", e);
            Err(ApiError::Bcrypt(e))
        }
    }
}
