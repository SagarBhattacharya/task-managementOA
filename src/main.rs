use crate::auth::auth_router;
use axum::Router;
use redis::Client;
use std::sync::Arc;
use sqlx::PgPool;
use tokio::net::TcpListener;
use crate::db::{TaskRepository, UserRepository};
use crate::postgres::PgRepository;
use crate::tasks::task_router;

mod models;
pub mod auth;
mod tasks;
mod jwt;
mod db;
mod postgres;

#[derive(Clone)]
pub struct AppState {
	pub redis: Client,
	pub jwt_secret: String,
	pub task_repository: Arc<dyn TaskRepository>,
	pub user_repository: Arc<dyn UserRepository>,
}

#[tokio::main]
async fn main() {
	let pgpool = PgPool::connect("postgres://admin:password@localhost:5432/tm")
		.await.unwrap();
	let repo = PgRepository::new(pgpool);

	let redis_client = connect().await.unwrap();
	let state = AppState {
		redis: redis_client,
		jwt_secret: "development-secret".to_string(),
		task_repository: Arc::new(repo.clone()),
		user_repository: Arc::new(repo),
	};

	let router = Router::new()
		.merge(auth_router())
		.merge(task_router(state.jwt_secret.clone()))
		.with_state(Arc::new(state));

	let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
	axum::serve(listener, router).await.unwrap();
}

pub async fn connect() -> redis::RedisResult<Client> {
	let client = Client::open("redis://127.0.0.1:6379")?;
	let mut conn = client.get_multiplexed_async_connection().await?;
	redis::cmd("PING")
		.query_async::<String>(&mut conn)
		.await?;
	Ok(client)
}