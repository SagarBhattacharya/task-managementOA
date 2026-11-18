use argon2::{Argon2, PasswordHash};
use async_trait::async_trait;
use password_hash::{PasswordHasher, PasswordVerifier};
use sqlx::PgPool;
use crate::db::{TaskRepository, UserRepository};
use crate::models::{Priority, Role, TaskRow, User};
use crate::tasks::{CreateTaskRequest, TaskResponse};

#[derive(Clone)]
pub struct PgRepository {
	pool: PgPool,
}

impl PgRepository {
	pub fn new(pool: PgPool) -> Self {
		Self { pool }
	}
}


#[async_trait]
impl UserRepository for PgRepository {
	async fn find_by_email(
		&self,
		email: &str,
	) -> Result<Option<User>, String> {
		let row = sqlx::query_as::<_, User>(
			"SELECT * FROM users WHERE email = $1"
		)
			.bind(email)
			.fetch_optional(&self.pool)
			.await
			.map_err(|e| e.to_string())?;

		Ok(row)
	}

	async fn find_by_id(
		&self,
		id: i64,
	) -> Result<Option<User>, String> {
		let row = sqlx::query_as::<_, User>(
			"SELECT * FROM users WHERE id = $1"
		)
			.bind(id)
			.fetch_optional(&self.pool)
			.await
			.map_err(|e| e.to_string())?;
		Ok(row)
	}

	async fn verify_password(
		&self,
		user: &User,
		password: &str,
	) -> Result<bool, String> {
		let hash = PasswordHash::new(&user.hashed_password)
			.map_err(|e| e.to_string())?;

		Ok(
			Argon2::default()
				.verify_password(password.as_bytes(), &hash)
				.is_ok()
		)
	}

	async fn hash_password(
		&self,
		password: &str,
	) -> Result<String, String> {
		Argon2::default()
			.hash_password(password.as_bytes())
			.map(|hash| hash.to_string())
			.map_err(|e| e.to_string())
	}

	async fn create_user(
		&self,
		full_name: &str,
		email: &str,
		hashed_password: &str,
		role: Role,
	) -> Result<User, String> {
		let role = match role {
			Role::Admin => "Admin",
			Role::Staff => "Staff",
		};

		let row = sqlx::query_as::<_, User>(
			r#"
				INSERT INTO users (
						full_name,
						email,
						hashed_password,
						role
				)
				VALUES ($1, $2, $3, $4)
				RETURNING *
			"#
		)
			.bind(full_name)
			.bind(email)
			.bind(hashed_password)
			.bind(role)
			.fetch_one(&self.pool)
			.await
			.map_err(|e| e.to_string())?;
		Ok(row)
	}
}

#[async_trait]
impl TaskRepository for PgRepository {
	async fn create_task(
		&self,
		request: CreateTaskRequest,
		created_by_id: i64,
	) -> Result<TaskResponse, String> {
		let priority = match request.priority {
			Priority::High => "High",
			Priority::Low => "Low",
		};

		let row = sqlx::query_as::<_, TaskRow>(
			r#"
            WITH inserted AS (
                INSERT INTO tasks (
                    title,
                    description,
                    status,
                    priority,
                    created_by_id,
                    assigned_to_id
                )
                SELECT
                    $1,
                    $2,
                    'Todo',
                    $3,
                    $4,
                    u.id
                FROM users u
                WHERE u.id = $5
                  AND u.role = 'Staff'
                RETURNING *
            )
            SELECT
                t.id,
                t.title,
                t.description,
                t.status,
                t.priority,
                t.created_by_id,
                u.email AS assigned_to_email,
                t.created_at,
                t.updated_at
            FROM inserted t
            JOIN users u ON u.id = t.assigned_to_id
            "#
		)
			.bind(&request.title)
			.bind(&request.description)
			.bind(priority)
			.bind(created_by_id)
			.bind(request.assigned_to_id)
			.fetch_optional(&self.pool)
			.await
			.map_err(|e| e.to_string())?
			.ok_or("Assigned staff member does not exist".to_string())?;

		TaskResponse::try_from(row)
	}

	async fn assign_task(
		&self,
		task_id: i64,
		staff_email: &str,
	) -> Result<TaskResponse, String> {
		let row = sqlx::query_as::<_, TaskRow>(
			r#"
            UPDATE tasks t
            SET
                assigned_to_id = u.id,
                updated_at = NOW()
            FROM users u
            WHERE t.id = $1
              AND u.email = $2
              AND u.role = 'Staff'
            RETURNING
                t.id,
                t.title,
                t.description,
                t.status,
                t.priority,
                t.created_by_id,
                u.email AS assigned_to_email,
                t.created_at,
                t.updated_at
            "#
		)
			.bind(task_id)
			.bind(staff_email)
			.fetch_optional(&self.pool)
			.await
			.map_err(|e| e.to_string())?
			.ok_or("Task or eligible staff member not found".to_string())?;

		TaskResponse::try_from(row)
	}
}