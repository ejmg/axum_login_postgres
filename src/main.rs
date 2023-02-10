use sqlx::{postgres::PgPoolOptions, PgPool};
use rand::Rng;
use std::{net::SocketAddr, sync::Arc};
use axum::{
    routing::{get, post},
    Router,
    response::{IntoResponse, Html}, http::StatusCode, extract::State
};


use axum_login::{
    axum_sessions::{async_session::MemoryStore as SessionMemoryStore, SessionLayer},
    memory_store::MemoryStore as AuthMemoryStore,
    AuthLayer, RequireAuthorizationLayer,
    AuthUser,
    secrecy::SecretVec
};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use serde::{Deserialize, Serialize};

const USERNAME: &'static str = "smiley";
const PW_HASH: &'static str = "thecircus";

#[derive(Serialize, Deserialize)]
struct LoginUser {
    username: String,
    pw_hash: String
}

#[derive(Debug, Clone, Deserialize, Serialize, sqlx::FromRow)]
struct User {
    id: i64,
    pw_hash: String
}

impl AuthUser for User {
    fn get_id(&self) -> String {
        format!("{}", self.id)
    }
    fn get_password_hash(&self) -> SecretVec<u8> {
        SecretVec::new(self.pw_hash.clone().into())
    }
}

type AuthContext = axum_login::extractors::AuthContext<User, axum_login::PostgresStore<User>>;

async fn private_route(
    axum::Extension(user): axum::Extension<User>
) -> impl IntoResponse {
    tracing::debug!("private route, authenticated as {user:?}");
    String::from("hi, {user}...")
}

async fn get_login(
    State(pool) : State<PgPool>,
    mut auth : AuthContext
) -> impl IntoResponse {
    let u = sqlx::query!(
        r#"
            SELECT id, username, pw_hash FROM users
            WHERE username=$1;
        "#,
        USERNAME
    )
    .fetch_one(&pool)
    .await.expect("Could not query example user");

    match auth.login(&User { id: u.id, pw_hash: u.pw_hash }).await {
        Ok(_) => Ok(format!("User logged in.")),
        Err(_) => Err("Couldn't login user...")
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_tokio_postgres=debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_cx_str = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://login_demo:password@localhost:5433/login_demo".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&db_cx_str)
        .await
        .expect("can't connect to DBS");

    let _ = sqlx::query!(
        r#"
            INSERT INTO users (username, pw_hash)
            VALUES ($1, $2)
            RETURNING id
        "#,
        USERNAME, PW_HASH
        )
        .fetch_one(&pool)
        .await.unwrap();

    let secret = rand::thread_rng().gen::<[u8; 64]>();

    let session_store = SessionMemoryStore::new();

    let session_layer = SessionLayer::new(session_store, &secret).with_secure(false);
    let user_store = axum_login::PostgresStore::<User>::new(pool.clone());
    let auth_layer = AuthLayer::new(user_store, &secret);

    let app = Router::new()
        .route("/private", get(private_route))
        .route_layer(RequireAuthorizationLayer::<User>::login())
        .route("/login", get(get_login))
        .layer(auth_layer)
        .layer(session_layer)
        .with_state(pool);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    tracing::debug!("starting application on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
