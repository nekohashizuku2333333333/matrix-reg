use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Form, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::{Client, StatusCode as ReqStatusCode};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::{error, info};

type HmacSha1 = Hmac<Sha1>;

static USERNAME_RE: Lazy<Regex> = Lazy::new(|| Regex::new("^[a-zA-Z0-9]+$").unwrap());

#[derive(Clone)]
struct AppConfig {
    token: String,
    server: String,
    shared_secret: String,
    bind_addr: SocketAddr,
}

impl AppConfig {
    fn from_env() -> Result<Self, ConfigError> {
        let token =
            std::env::var("MATRIX_TOKEN").map_err(|_| ConfigError::Missing("MATRIX_TOKEN"))?;
        let server =
            std::env::var("MATRIX_SERVER").map_err(|_| ConfigError::Missing("MATRIX_SERVER"))?;
        let shared_secret = std::env::var("MATRIX_SHARED_SECRET")
            .map_err(|_| ConfigError::Missing("MATRIX_SHARED_SECRET"))?;
        let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
            .parse()
            .map_err(|_| ConfigError::InvalidBindAddr)?;

        Ok(Self {
            token,
            server: server.trim_end_matches('/').to_string(),
            shared_secret,
            bind_addr,
        })
    }
}

#[derive(Debug, Error)]
enum ConfigError {
    #[error("missing required env var {0}")]
    Missing(&'static str),
    #[error("invalid BIND_ADDR; expected host:port")]
    InvalidBindAddr,
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    attempts: Attempts,
    client: Client,
}

type Attempts = std::sync::Arc<DashMap<IpAddr, Attempt>>;

#[derive(Clone, Debug)]
struct Attempt {
    count: u32,
    last: DateTime<Utc>,
}

impl AppState {
    fn new(config: AppConfig) -> Self {
        let client = Client::builder().build().expect("reqwest client");
        Self {
            config,
            attempts: std::sync::Arc::new(DashMap::new()),
            client,
        }
    }

    fn too_many_requests(&self, ip: IpAddr) -> bool {
        if let Some(mut entry) = self.attempts.get_mut(&ip) {
            let elapsed = Utc::now() - entry.last;
            if elapsed > chrono::Duration::hours(24) {
                entry.count = 0;
                entry.last = Utc::now();
                return false;
            }
            return entry.count >= 3;
        }
        false
    }

    fn record_attempt(&self, ip: IpAddr) {
        let now = Utc::now();
        self.attempts
            .entry(ip)
            .and_modify(|attempt| {
                attempt.count += 1;
                attempt.last = now;
            })
            .or_insert(Attempt {
                count: 1,
                last: now,
            });
    }

    fn is_token_ok(&self, token: &str) -> bool {
        self.config.token == token
    }

    async fn register_user(&self, username: &str, password: &str) -> Result<(), RegisterError> {
        let nonce = self.fetch_nonce().await?;
        let mac = calculate_mac(&nonce, username, password, &self.config.shared_secret);
        let body = RegisterUserRequest {
            nonce,
            username,
            password,
            admin: false,
            mac,
        };

        let url = format!("{}/_synapse/admin/v1/register", self.config.server);
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(RegisterError::Upstream)?;

        match response.status() {
            ReqStatusCode::OK => Ok(()),
            ReqStatusCode::BAD_REQUEST => Err(RegisterError::UserExists),
            status => {
                let text = response.text().await.unwrap_or_default();
                Err(RegisterError::UnexpectedStatus(status, text))
            }
        }
    }

    async fn fetch_nonce(&self) -> Result<String, RegisterError> {
        let url = format!("{}/_synapse/admin/v1/register", self.config.server);
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(RegisterError::Upstream)?
            .error_for_status()
            .map_err(|e| {
                RegisterError::UnexpectedStatus(
                    e.status().unwrap_or(ReqStatusCode::INTERNAL_SERVER_ERROR),
                    e.to_string(),
                )
            })?;

        let payload: NonceResponse = response.json().await.map_err(RegisterError::Upstream)?;
        Ok(payload.nonce)
    }
}

#[derive(Debug, Error)]
enum RegisterError {
    #[error("user exists")]
    UserExists,
    #[error("upstream error: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("unexpected upstream status {0}: {1}")]
    UnexpectedStatus(ReqStatusCode, String),
}

#[derive(Deserialize)]
struct RegisterForm {
    username: String,
    password: String,
    #[serde(rename = "passwordConfirmation", default)]
    password_confirmation: String,
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RegistrationState {
    Registered,
    InvalidUserOrPass,
    Blocked,
    InvalidToken,
    InvalidUsername,
    InvalidPassword,
    InvalidPasswordVerification,
    UserExists,
    InternalError,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationResponse {
    registration_state: RegistrationState,
    username: String,
}

#[derive(Serialize)]
struct RegisterUserRequest<'a> {
    nonce: String,
    username: &'a str,
    password: &'a str,
    admin: bool,
    mac: String,
}

#[derive(Deserialize)]
struct NonceResponse {
    nonce: String,
}

fn validate_username(username: &str) -> bool {
    USERNAME_RE.is_match(username)
}

fn validate_password(password: &str) -> bool {
    password.len() >= 3 && !password.chars().any(char::is_whitespace)
}

fn calculate_mac(nonce: &str, user: &str, password: &str, shared_secret: &str) -> String {
    let mut mac = HmacSha1::new_from_slice(shared_secret.as_bytes()).expect("hmac can take key");

    mac.update(nonce.as_bytes());
    mac.update(&[0]);
    mac.update(user.as_bytes());
    mac.update(&[0]);
    mac.update(password.as_bytes());
    mac.update(&[0]);
    mac.update(b"notadmin");

    hex::encode(mac.finalize().into_bytes())
}

async fn register_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> impl IntoResponse {
    let client_ip = extract_ip(&headers).unwrap_or_else(|| addr.ip());

    if form.username.is_empty() {
        return response(
            StatusCode::OK,
            RegistrationState::InvalidUsername,
            &form.username,
        );
    }
    if form.password.is_empty() {
        return response(
            StatusCode::OK,
            RegistrationState::InvalidPassword,
            &form.username,
        );
    }
    if form.token.is_empty() {
        return response(
            StatusCode::OK,
            RegistrationState::InvalidToken,
            &form.username,
        );
    }

    if state.too_many_requests(client_ip) {
        return response(StatusCode::OK, RegistrationState::Blocked, &form.username);
    }

    if form.password != form.password_confirmation {
        return response(
            StatusCode::OK,
            RegistrationState::InvalidPasswordVerification,
            &form.username,
        );
    }

    if !validate_username(&form.username) || !validate_password(&form.password) {
        return response(
            StatusCode::OK,
            RegistrationState::InvalidUserOrPass,
            &form.username,
        );
    }

    if !state.is_token_ok(&form.token) {
        state.record_attempt(client_ip);
        return response(
            StatusCode::OK,
            RegistrationState::InvalidToken,
            &form.username,
        );
    }

    let result = state.register_user(&form.username, &form.password).await;
    state.record_attempt(client_ip);

    match result {
        Ok(_) => response(
            StatusCode::OK,
            RegistrationState::Registered,
            &form.username,
        ),
        Err(RegisterError::UserExists) => response(
            StatusCode::UNPROCESSABLE_ENTITY,
            RegistrationState::UserExists,
            &form.username,
        ),
        Err(err) => {
            error!("registration failed: {err}");
            response(
                StatusCode::INTERNAL_SERVER_ERROR,
                RegistrationState::InternalError,
                &form.username,
            )
        }
    }
}

fn response(
    status: StatusCode,
    registration_state: RegistrationState,
    username: &str,
) -> (StatusCode, Json<RegistrationResponse>) {
    (
        status,
        Json(RegistrationResponse {
            registration_state,
            username: username.to_string(),
        }),
    )
}

fn extract_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.split(',').next())
        .and_then(|part| part.trim().parse().ok())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = AppConfig::from_env()?;
    info!(
        "Starting Matrix registration bridge on {}",
        config.bind_addr
    );

    let bind_addr = config.bind_addr;
    let state = AppState::new(config);

    let app = Router::new()
        .route("/registration", post(register_handler))
        .with_state(state);

    let listener = TcpListener::bind(bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
