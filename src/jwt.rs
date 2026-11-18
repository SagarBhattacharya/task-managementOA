use axum::{
	body::Body,
	extract::State,
	http::{Request, StatusCode},
	middleware::Next,
	response::Response,
};
use jsonwebtoken::{
	decode,
	Algorithm,
	DecodingKey,
	Validation,
};

use crate::auth::Claims;
use crate::models::{AuthUser, Role};

pub async fn require_admin(
	State(secret): State<String>,
	mut request: Request<Body>,
	next: Next,
) -> Result<Response, StatusCode> {
	let token = request
		.headers()
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "))
		.ok_or(StatusCode::UNAUTHORIZED)?;

	let claims = decode::<Claims>(
		token,
		&DecodingKey::from_secret(secret.as_bytes()),
		&Validation::new(Algorithm::HS256),
	)
		.map_err(|_| StatusCode::UNAUTHORIZED)?
		.claims;

	if !matches!(claims.role, Role::Admin) {
		return Err(StatusCode::FORBIDDEN);
	}

	request.extensions_mut().insert(AuthUser {
		user_id: claims.sub,
		role: claims.role,
	});

	Ok(next.run(request).await)
}