use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use serde_json::json;

use crate::auth::models::{LoginRequest, RegisterRequest};
use crate::auth::{db, jwt, password};
use crate::state::AppState;

pub fn auth_router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login_handler))
        .route("/register", post(register_handler))
}

pub async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let db_pool = &state.db_pool;
    let username = payload.username.clone();

    let existing_user = db::find_user_by_username(db_pool, &username).await;

    match existing_user {
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "User already exists"})),
            )
                .into_response();
        }
        Err(e) => {
            eprintln!("Database error checking for user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        Ok(None) => {
            // Username is available, continue
        }
    }

    let hashed_password = match password::hash_password(payload.password.clone()).await {
        Ok(hash) => hash,
        Err(e) => {
            eprintln!("Error hashing password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Error hashing password"})),
            )
                .into_response();
        }
    };

    println!("Axum Register: Creating user in database."); // Added log
    match db::create_user(db_pool, &payload.username, &hashed_password).await {
        Ok(_) => {
            println!("Axum Register: User created successfully."); // Added log
            (
                StatusCode::CREATED,
                Json(json!({"message": "User registered successfully!"})),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("Database error creating user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error creating user"})),
            )
                .into_response()
        }
    }
}

pub async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let db_pool = &state.db_pool;
    let jwt_secret = &state.jwt_secret;
    let username = payload.username.clone();

    let existing_user = db::find_user_by_username(db_pool, &username).await;

    let user = match existing_user {
        Ok(Some(user)) => {
            // user exists, now verify the password
            user
        }
        Err(e) => {
            eprintln!("Database error checking for user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Database error"})),
            )
                .into_response();
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Invalid username or password"})),
            )
                .into_response();
        }
    };

    let password = payload.password;
    let check_password = match password::verify_password(password, user.password_hash.clone()).await
    {
        Ok(is_valid) => is_valid,
        Err(e) => {
            eprintln!("Error verifying password: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Error verifying password"})),
            )
                .into_response();
        }
    };

    if !check_password {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid username or password"})),
        )
            .into_response();
    }

    let token = match jwt::generate_token(user.id, &username, jwt_secret) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Error creating JWT: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Error creating token"})),
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(json!({"token": token}))).into_response()
}
