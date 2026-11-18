use async_trait::async_trait;
use crate::models::{Role, User};
use crate::tasks::{
	CreateTaskRequest,
	TaskResponse,
};

#[async_trait]
pub trait TaskRepository: Send + Sync {
	async fn create_task(
		&self,
		request: CreateTaskRequest,
		created_by_id: i64,
	) -> Result<TaskResponse, String>;

	async fn assign_task(
		&self,
		task_id: i64,
		staff_email: &str,
	) -> Result<TaskResponse, String>;
}

#[async_trait]
pub trait UserRepository: Send + Sync {
	async fn find_by_email(
		&self,
		email: &str,
	) -> Result<Option<User>, String>;

	async fn find_by_id(
		&self,
		id: i64,
	) -> Result<Option<User>, String>;

	async fn verify_password(
		&self,
		user: &User,
		password: &str,
	) -> Result<bool, String>;

	async fn hash_password(
		&self,
		password: &str,
	) -> Result<String, String>;

	async fn create_user(
		&self,
		full_name: &str,
		email: &str,
		hashed_password: &str,
		role: Role,
	) -> Result<User, String>;
}
