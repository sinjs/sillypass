mod model;

use std::{env, process};

use actix_jwt_auth_middleware::{
    use_jwt::{UseJWTOnApp, UseJWTOnScope},
    AuthResult, Authority, TokenSigner,
};
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use dotenvy::dotenv;
use ed25519_compact::{KeyPair, Seed};
use jwt_compact::alg::Ed25519;

use actix_web::{get, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder};
use log::{error, info};
use model::{JwtUserModel, UserModel};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};

pub struct AppState<'a> {
    db: PgPool,
    argon2: Argon2<'a>,
}

#[get("/")]
async fn index(state: web::Data<AppState<'_>>) -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[derive(Serialize, Deserialize, Debug)]
struct LoginSchema {
    pub email: String,
    pub password_hash: String,
}

fn sign_and_respond(
    jwt_signer: web::Data<TokenSigner<JwtUserModel, Ed25519>>,
    user: JwtUserModel,
) -> Result<HttpResponse> {
    let (access_token, refresh_token) = {
        let access_token = jwt_signer
            .create_access_header_value(&user)
            .map_err(|e| anyhow::format_err!("{:?}", e))?;
        let refresh_token = jwt_signer
            .create_refresh_header_value(&user)
            .map_err(|e| anyhow::format_err!("{:?}", e))?;

        let access_token = access_token.to_str()?.to_string(); // Convert to `String`
        let refresh_token = refresh_token.to_str()?.to_string(); // Convert to `String`

        (access_token, refresh_token)
    };

    Ok(HttpResponse::Ok()
        .cookie(
            jwt_signer
                .create_access_cookie(&user)
                .map_err(|e| anyhow::format_err!("{:?}", e))?,
        )
        .cookie(
            jwt_signer
                .create_refresh_cookie(&user)
                .map_err(|e| anyhow::format_err!("{:?}", e))?,
        )
        .json(json!({"access_token": access_token, "refresh_token": refresh_token})))
}

#[post("/auth/login")]
async fn login(
    jwt_signer: web::Data<TokenSigner<JwtUserModel, Ed25519>>,
    body: web::Json<LoginSchema>,
    data: web::Data<AppState<'_>>,
) -> impl Responder {
    let user = match sqlx::query_as!(
        UserModel,
        r#"SELECT * FROM users WHERE email = $1"#,
        body.email.to_string()
    )
    .fetch_one(&data.db)
    .await
    {
        Ok(user) => user,
        Err(error) => match error {
            sqlx::Error::RowNotFound => {
                return HttpResponse::Forbidden().json(
                    json!({ "message": "User with matching username and password not found." }),
                )
            }
            _ => {
                return HttpResponse::InternalServerError()
                    .json(json!({"message": "Internal Server Error"}))
            }
        },
    };

    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({"message": "Internal Server Error"}))
        }
    };

    if let Err(err) = data
        .argon2
        .verify_password(body.password_hash.as_bytes(), &parsed_hash)
    {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "User with matching username and password not found." }));
    }

    let user_claim = JwtUserModel { id: user.id };

    return match sign_and_respond(jwt_signer, user_claim) {
        Ok(response) => response,
        Err(error) => {
            HttpResponse::InternalServerError().json(json!({"message": "Internal Server Error"}))
        }
    };
}

fn config(conf: &mut web::ServiceConfig) {
    let api = web::scope("/api");

    conf.service(index).service(api);
}

fn convert_string_to_seed(string: String) -> Result<Seed> {
    if string.len() != 32 {
        return Err(anyhow!("The length of the seed must be 32 bytes"));
    }

    let mut array = [0u8; 32];
    let bytes = string.as_bytes();

    let len = bytes.len().min(32);
    array[..len].copy_from_slice(&bytes[..len]);

    let seed = Seed::from_slice(&array);

    Ok(seed?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    dotenv().ok();
    env_logger::init();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let seed = env::var("JWT_SECRET_SEED").expect("JWT_SECRET_SEED must be set");

    let seed = convert_string_to_seed(seed)
        .expect("Failed to convert JWT_SECRET_SEED to a valid seed object");

    let pool = match PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(err) => {
            error!("Failed to connect to the database: {:?}", err);
            process::exit(1);
        }
    };
    info!("Connected to the database");
    info!("Starting up server");

    let KeyPair {
        pk: public_key,
        sk: secret_key,
    } = KeyPair::from_seed(seed);

    HttpServer::new(move || {
        let authority = Authority::<JwtUserModel, Ed25519, _, _>::new()
            .refresh_authorizer(|| async move { Ok(()) })
            .token_signer(Some(
                TokenSigner::new()
                    .signing_key(secret_key.clone())
                    .algorithm(Ed25519)
                    .build()
                    .expect(""),
            ))
            .verifying_key(public_key)
            .build()
            .expect("");

        App::new()
            .app_data(web::Data::new(AppState {
                db: pool.clone(),
                argon2: Argon2::default(),
            }))
            .use_jwt(authority, web::scope("").configure(config))
            .wrap(Logger::default())
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
