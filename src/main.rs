use axum::{Router, response::IntoResponse, routing::get};
use dotenv::dotenv;
use sqlx::PgPool;
use std::env;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

mod auth;
mod state;

use crate::state::AppState;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let db_pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to the database");

    let state = AppState {
        db_pool: db_pool.clone(),
        jwt_secret: jwt_secret.clone(),
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/health", get(health_check_handler))
        .nest("/api/auth", auth::handlers::auth_router())
        .with_state(state)
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind("0.0.0.0:3001").await.unwrap();
    println!("Listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

async fn health_check_handler() -> impl IntoResponse {
    "Ariel B Wang <3"
}
