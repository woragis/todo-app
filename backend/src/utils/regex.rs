use log::error;
use regex::Regex;

use crate::models::response::ApiError;

pub fn regex_email(email: &str) -> Result<(), ApiError> {
    let email_regex =
        Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").map_err(|e| {
            error!("Error in email regex: {}", e);
            ApiError::RegexValidationError(format!("{}", e))
        })?;

    match email_regex.is_match(email) {
        false => return Err(ApiError::RegexValidationError("email invalid".to_string())),
        true => Ok(()),
    }
}

pub fn regex_password(password: &str) -> Result<(), ApiError> {
    let password_regex = Regex::new(r"^[A-Za-z0-9!@#$%^&*()_\-]{8,}$").map_err(|e| {
        error!("Error in password regex: {}", e);
        ApiError::RegexValidationError(format!("{}", e))
    })?;

    match password_regex.is_match(password) {
        false => {
            return Err(ApiError::RegexValidationError(
                "password invalid".to_string(),
            ))
        }
        true => Ok(()),
    }
}
