use sqlx::{Error, PgPool};
use uuid::Uuid;

use crate::auth::models::User;

pub async fn create_user(
    pool: &PgPool,
    username: &str,
    password_hash: &str,
) -> Result<User, Error> {
    sqlx::query_as!(
        User,
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *",
        username,
        password_hash
    )
    .fetch_one(pool)
    .await
}

pub async fn find_user_by_username(
    db_pool: &PgPool,
    username: &str,
) -> Result<Option<User>, Error> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE username = $1
        "#,
        username
    )
    .fetch_optional(db_pool)
    .await?;

    Ok(user)
}

pub async fn find_user_by_id(db_pool: &PgPool, user_id: Uuid) -> Result<Option<User>, Error> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT * FROM users WHERE id = $1
        "#,
        user_id
    )
    .fetch_optional(db_pool)
    .await?;

    Ok(user)
}
