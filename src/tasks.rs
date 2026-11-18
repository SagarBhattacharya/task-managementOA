use std::sync::Arc;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{AuthUser, Priority, TaskStatus};

use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, Extension, Json, Router, middleware};
use axum::routing::post;
use crate::AppState;
use crate::jwt::require_admin;

#[derive(Debug, Deserialize)]
pub struct CreateTaskRequest {
	pub title: String,
	pub description: String,
	pub priority: Priority,
	pub assigned_to_id: i64,
}

#[derive(Debug, Serialize)]
pub struct TaskResponse {
	pub id: i64,
	pub title: String,
	pub description: String,
	pub status: TaskStatus,
	pub priority: Priority,
	pub created_by_id: i64,
	pub assigned_to_email: String,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AssignTaskRequest {
	pub task_id: i64,
	pub email: String,
}

pub fn task_router(jwt_secret: String) -> Router<Arc<AppState>> {
	Router::new()
		.route("/tasks", post(create_task))
		.route("/tasks/assign", post(assign_task))
		.route_layer(
			middleware::from_fn_with_state(
				jwt_secret,
				require_admin,
			)
		)
}

pub async fn create_task(
	State(state): State<Arc<AppState>>,
	Extension(auth_user): Extension<AuthUser>,
	Json(payload): Json<CreateTaskRequest>,
) -> Response {

	let result = state.task_repository
		.create_task(payload, auth_user.user_id)
		.await;

	match result {
		Ok(task) => (
			StatusCode::CREATED,
			Json(task),
		).into_response(),

		Err(error) => {
			eprintln!("Task creation failed: {error}");
			StatusCode::INTERNAL_SERVER_ERROR.into_response()
		}
	}
}

pub async fn assign_task(
	State(state): State<Arc<AppState>>,
	Extension(auth_user): Extension<AuthUser>,
	Json(payload): Json<AssignTaskRequest>,
) -> Response {
	// Admin authorization is already enforced by middleware.

	let result = state.task_repository
		.assign_task(
			payload.task_id,
			&payload.email,
		)
		.await;

	match result {
		Ok(task) => (
			StatusCode::OK,
			Json(task),
		).into_response(),

		Err(error) => {
			eprintln!("Task assignment failed: {error}");
			StatusCode::BAD_REQUEST.into_response()
		}
	}
}