use bcrypt::{hash, verify, BcryptError};

pub fn hash_password(password: &str) -> Result<String, BcryptError> {
    match hash(password, 12) {
        Ok(hash) => Ok(hash),
        Err(e) => Err(e)
    }
}

pub fn compare_password(password: &str, hash: &str) -> Result<bool, BcryptError> {
    match verify(password, hash) {
        Ok(is_equal) => Ok(is_equal),
        Err(e) => Err(e),
    }
}