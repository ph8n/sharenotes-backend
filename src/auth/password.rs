use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use tokio::task;

pub async fn hash_password(password: String) -> Result<String, argon2::password_hash::Error> {
    task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
    })
    .await
    .expect("Task spawned for password hashing panicked")
}

pub async fn verify_password(
    password: String,
    hash: String,
) -> Result<bool, argon2::password_hash::Error> {
    task::spawn_blocking(move || {
        let parsed_hash = match argon2::PasswordHash::new(&hash) {
            Ok(h) => h,
            Err(e) => return Err(e),
        };
        let argon2 = Argon2::default();

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true), // Verification successful
            Err(e) => match e {
                argon2::password_hash::Error::Password => Ok(false),
                _ => Err(e),
            },
        }
    })
    .await
    .expect("Task spawned for password verification panicked")
}
