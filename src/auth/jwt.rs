use crate::auth::models::Claims;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use uuid::Uuid;

pub fn generate_token(
    user_id: Uuid,
    username: &str,
    jwt_secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claim = Claims {
        sub: user_id,
        username: username.to_string(),
        exp: (Utc::now() + Duration::hours(24)).timestamp(),
        iat: Utc::now().timestamp(),
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(jwt_secret.as_ref());

    let token = encode(&header, &claim, &encoding_key).map_err(|e| {
        eprintln!("Error encoding token: {}", e);
        e
    })?;
    Ok(token)
}

pub fn verify_token(token: &str, jwt_secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    let decoded_token = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
        eprintln!("Error decoding token: {}", e);
        e
    })?;
    Ok(decoded_token.claims)
}
