use actix_web::{web::{delete, get, put, scope}, Scope};

use crate::handlers::profile::{delete_user_profile, get_user_profile, update_user_profile};

pub fn profile_routes() -> Scope {
    scope("/profile")
    .route("/", get().to(get_user_profile))
    .route("/update", put().to(update_user_profile))
    .route("/delete", delete().to(delete_user_profile))
}
