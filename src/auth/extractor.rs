#![allow(unused)]
use axum::Json;
use axum::extract::FromRef;
use axum::extract::{FromRequestParts, State};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use sqlx::Error as SqlxError;

use crate::auth::models::{AuthenticatedUser, Claims, User};
use crate::auth::{db, jwt};
use crate::state::AppState;

pub enum AuthError {
    MissingToken,
    InvalidToken,
    InvalidTokenSignature,
    ExpiredToken,
    UserNotFound,
    InternalError(String),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_msg) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token".to_string()),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token".to_string()),
            AuthError::InvalidTokenSignature => (
                StatusCode::UNAUTHORIZED,
                "Invalid token signature".to_string(),
            ),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, "Expired token".to_string()),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            AuthError::InternalError(msg) => {
                eprintln!("Internal authentication error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal error occurred".to_string(),
                )
            }
        };
        let body = Json(json!({
            "error: ": error_msg,
        }));

        (status, body).into_response()
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let db_pool = &state.db_pool;
        let jwt_secret = &state.jwt_secret;
        let headers = &parts.headers;

        let auth_header = headers
            .get(axum::http::header::AUTHORIZATION)
            .ok_or(AuthError::MissingToken)?;
        let auth_value = auth_header.to_str().map_err(|_| AuthError::InvalidToken)?;
        let token = auth_value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidToken)?;

        let claims = jwt::verify_token(token, jwt_secret).map_err(|e| {
            eprintln!("JWT verification error: {}", e);
            AuthError::InvalidTokenSignature
        })?;

        let user_id = claims.sub;
        let user = db::find_user_by_id(db_pool, user_id)
            .await
            .map_err(|e| {
                eprintln!("Database error fetching user by ID: {}", e);
                AuthError::InternalError("Database error fetching user".to_string())
            })?
            .ok_or(AuthError::UserNotFound)?;

        Ok(AuthenticatedUser {
            id: user.id,
            username: user.username,
        })
    }
}
