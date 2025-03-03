use bcrypt::{hash, verify, BcryptError};
use log::{debug, error};

pub fn hash_password(password: &str) -> Result<String, BcryptError> {
    match hash(password, 12) {
        Ok(hash) => {
            debug!("Hashed password: {} to {}", password, hash);
            Ok(hash)
        }
        Err(e) => {
            error!("Bcrypt error: {}", e);
            Err(e)
        }
    }
}

pub fn compare_password(password: &str, hash: &str) -> Result<bool, BcryptError> {
    match verify(password, hash) {
        Ok(is_equal) => {
            debug!("comparing password... is equal?: {}", is_equal);
            Ok(is_equal)
        }
        Err(e) => {
            error!("Bcrypt error: {}", e);
            Err(e)
        }
    }
}
