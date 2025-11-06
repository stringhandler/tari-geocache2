use axum::{Router, routing::get, routing::post};
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

use crate::handlers::{
    admin_authenticate, admin_info, admin_page, create_geocache, get_address_json, get_geocache,
    get_geocaches, get_guestbook, print_address, scan, AppState,
};

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/geocaches", post(create_geocache))
        .route("/api/geocaches", get(get_geocaches))
        .route("/api/geocaches/:id", get(get_geocache))
        .route("/api/guestbook/:short_id", get(get_guestbook))
        .route("/api/scan/:short_id", get(scan))
        .route("/api/address/:short_id", get(get_address_json))
        .route(
            "/api/admin/:short_id/authenticate",
            post(admin_authenticate),
        )
        .route("/api/admin/:short_id/info", get(admin_info))
        .route("/admin/:short_id", get(admin_page))
        .route("/print/:short_id", get(print_address))
        .nest_service("/", ServeDir::new("static"))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
