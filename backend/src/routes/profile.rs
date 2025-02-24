use actix_web::{
    web::{delete, get, post, put, scope},
    Scope,
};

use crate::handlers::profile::{add_or_edit_profile_picture, delete_profile_picture, delete_user_profile, get_user_profile, update_user_profile};

pub fn profile_routes() -> Scope {
    scope("/profile")
        .route("/", get().to(get_user_profile))
        .route("/update", put().to(update_user_profile))
        .route("/delete", delete().to(delete_user_profile))
        .service(scope("/profile-picture")
            .route("/upload", post().to(add_or_edit_profile_picture))
            .route("/edit", put().to(add_or_edit_profile_picture))
            .route("/delete", delete().to(delete_profile_picture))
        )
}
