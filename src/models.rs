use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use crate::tasks::TaskResponse;

#[derive(Debug, Deserialize, Serialize)]
#[derive(FromRow)]
pub struct User {
	pub id: i64,
	pub full_name: String,
	pub email: String,
	pub hashed_password: String,
	pub role: Role,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>
}

#[derive(FromRow)]
pub struct TaskRow {
	id: i64,
	title: String,
	description: String,
	status: String,
	priority: String,
	created_by_id: i64,
	assigned_to_email: String,
	created_at: DateTime<Utc>,
	updated_at: DateTime<Utc>,
}

impl TryFrom<TaskRow> for TaskResponse {
	type Error = String;

	fn try_from(row: TaskRow) -> Result<Self, Self::Error> {
		use crate::models::{Priority, TaskStatus};

		let status = match row.status.as_str() {
			"Todo" => TaskStatus::Todo,
			"Done" => TaskStatus::Done,
			_ => return Err("Invalid task status".into()),
		};

		let priority = match row.priority.as_str() {
			"High" => Priority::High,
			"Low" => Priority::Low,
			_ => return Err("Invalid task priority".into()),
		};

		Ok(TaskResponse {
			id: row.id,
			title: row.title,
			description: row.description,
			status,
			priority,
			created_by_id: row.created_by_id,
			assigned_to_email: row.assigned_to_email,
			created_at: row.created_at,
			updated_at: row.updated_at,
		})
	}
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[serde(rename_all = "PascalCase")]
pub enum Role {
	Admin,
	Staff,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[serde(rename_all = "PascalCase")]
pub enum TaskStatus {
	Todo,
	Done,
}

#[derive(Debug, Clone, Serialize, Deserialize, Type)]
#[serde(rename_all = "PascalCase")]
pub enum Priority {
	High,
	Low,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
	pub user_id: i64,
	pub role: Role,
}

