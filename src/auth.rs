use std::sync::Arc;
use axum::{
	extract::{Query, State},
	http::StatusCode,
	response::{IntoResponse, Response},
	routing::{get, post},
	Json, Router,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::{Rng, RngExt};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::AppState;
use crate::models::Role;

const OTP_TTL: u64 = 300;
const JWT_TTL: u64 = 3600;

#[derive(Deserialize)]
pub struct AuthRequest {
	pub email: String,
	pub password: String,
	pub full_name: Option<String>,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
	pub email: String,
	pub otp_code: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
	pub access_token: String,
	pub token_type: String,
}

#[derive(Deserialize)]
pub struct LatestOtpQuery {
	pub email: String,
}

#[derive(Serialize)]
pub struct LatestOtpResponse {
	pub email: String,
	pub otp_code: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginChallenge {
	pub email: String,
	pub otp_code: String,
	pub expires_at: u64,

	// Existing user
	pub user_id: Option<i64>,

	// New user registration
	pub full_name: Option<String>,
	pub hashed_password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
	pub sub: i64,
	pub role: Role,
	pub exp: usize,
}

pub fn auth_router() -> Router<Arc<AppState>> {
	Router::new()
		.route("/auth/login", post(login))
		.route("/auth/verify-2fa", post(verify))
		.route("/dev/email-logs/latest", get(latest_otp))
}

pub async fn login(
	State(state): State<Arc<AppState>>,
	Json(payload): Json<AuthRequest>,
) -> Response {
	let user_repository = &state.user_repository;

	// Check whether the user already exists.
	let user = match user_repository
		.find_by_email(&payload.email)
		.await
	{
		Ok(user) => user,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let (user_id, full_name, hashed_password) = match user {
		// Existing user: validate password.
		Some(user) => {
			let valid = match user_repository
				.verify_password(&user, &payload.password)
				.await
			{
				Ok(valid) => valid,
				Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
			};

			if !valid {
				return StatusCode::UNAUTHORIZED.into_response();
			}

			(Some(user.id), None, None)
		}

		// New user: prepare registration.
		None => {
			let Some(full_name) = payload.full_name else {
				return StatusCode::BAD_REQUEST.into_response();
			};

			let hashed_password = match user_repository
				.hash_password(&payload.password)
				.await
			{
				Ok(hash) => hash,
				Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
			};

			(None, Some(full_name), Some(hashed_password))
		}
	};

	let otp_code = rand::rng()
		.random_range(100_000..=999_999)
		.to_string();

	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();

	let challenge = LoginChallenge {
		email: payload.email.clone(),
		otp_code,
		expires_at: now + OTP_TTL,
		user_id,
		full_name,
		hashed_password,
	};

	let key = format!("auth:challenge:{}", payload.email);

	let mut conn = match state.redis
		.get_multiplexed_async_connection()
		.await
	{
		Ok(conn) => conn,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let challenge_json = match serde_json::to_string(&challenge) {
		Ok(value) => value,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let result: redis::RedisResult<()> = conn
		.set_ex(&key, challenge_json, OTP_TTL)
		.await;

	if result.is_err() {
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	}

	// TODO: Send OTP to challenge.email.

	StatusCode::ACCEPTED.into_response()
}

pub async fn verify(
	State(state): State<Arc<AppState>>,
	Json(payload): Json<VerifyRequest>,
) -> Response {
	let key = format!("auth:challenge:{}", payload.email);

	let mut conn = match state.redis
		.get_multiplexed_async_connection()
		.await
	{
		Ok(conn) => conn,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let stored: Option<String> = match conn.get(&key).await {
		Ok(value) => value,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let Some(stored) = stored else {
		return StatusCode::UNAUTHORIZED.into_response();
	};

	let challenge: LoginChallenge = match serde_json::from_str(&stored) {
		Ok(value) => value,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let now = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();

	if now >= challenge.expires_at {
		let _: redis::RedisResult<()> = conn.del(&key).await;
		return StatusCode::UNAUTHORIZED.into_response();
	}

	if challenge.otp_code != payload.otp_code {
		return StatusCode::UNAUTHORIZED.into_response();
	}

	// Resolve the user after successful email verification.
	let user = if let Some(user_id) = challenge.user_id {
		// Existing user.
		match state.user_repository.find_by_id(user_id).await {
			Ok(Some(user)) => user,
			Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
			Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
		}
	} else {
		// New user: create only after OTP verification.
		let (Some(full_name), Some(hashed_password)) = (
			challenge.full_name.as_deref(),
			challenge.hashed_password.as_deref(),
		) else {
			return StatusCode::INTERNAL_SERVER_ERROR.into_response();
		};

		match state.user_repository.create_user(
			full_name,
			&challenge.email,
			hashed_password,
			Role::Staff,
		).await {
			Ok(user) => user,
			Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
		}
	};

	// Consume challenge.
	let _: redis::RedisResult<()> = conn.del(&key).await;

	let claims = Claims {
		sub: user.id,
		role: user.role,
		exp: (now + JWT_TTL) as usize,
	};

	let token = match encode(
		&Header::default(),
		&claims,
		&EncodingKey::from_secret(state.jwt_secret.as_bytes()),
	) {
		Ok(token) => token,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	Json(AuthResponse {
		access_token: token,
		token_type: "Bearer".into(),
	}).into_response()
}

pub async fn latest_otp(
	State(state): State<Arc<AppState>>,
	Query(query): Query<LatestOtpQuery>,
) -> Response {
	let key = format!("auth:challenge:{}", query.email);

	let mut conn = match state.redis
		.get_multiplexed_async_connection()
		.await
	{
		Ok(conn) => conn,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let stored: Option<String> = match conn.get(&key).await {
		Ok(value) => value,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	let Some(stored) = stored else {
		return StatusCode::NOT_FOUND.into_response();
	};

	let challenge: LoginChallenge = match serde_json::from_str(&stored) {
		Ok(value) => value,
		Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
	};

	Json(LatestOtpResponse {
		email: challenge.email,
		otp_code: challenge.otp_code,
	}).into_response()
}