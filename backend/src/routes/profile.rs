use actix_web::{
    web::{delete, get, post, put, scope},
    Scope,
};

use crate::handlers::profile::{
    add_or_edit_profile_picture, delete_profile_picture, delete_user_profile, get_profile_picture, get_user_profile, update_user_password, update_user_profile
};

pub fn profile_routes() -> Scope {
    scope("/profile")
        .route("/", get().to(get_user_profile))
        .route("/update", put().to(update_user_profile))
        .route("/update-password", put().to(update_user_password))
        .route("/delete", delete().to(delete_user_profile))
        .route("/profile-picture/view", get().to(get_profile_picture))
        .route(
            "/profile-picture/upload",
            post().to(add_or_edit_profile_picture),
        )
        .route(
            "/profile-picture/edit",
            put().to(add_or_edit_profile_picture),
        )
        .route(
            "/profile-picture/delete",
            delete().to(delete_profile_picture),
        )
}
