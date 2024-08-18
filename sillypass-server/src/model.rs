use actix_jwt_auth_middleware::FromRequest;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct UserModel {
    pub id: i32,
    pub email: String,
    pub password_hash: String,
    pub client_salt: String,
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct VaultModel {
    pub id: Uuid,
    pub user_id: i32,
    pub secret_access_key: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, FromRequest)]
pub struct JwtUserModel {
    pub id: i32,
}
