-- Add migration script here
create table users (
	id bigint generated always as identity primary key,
	full_name text not null,
	email text not null,
	hashed_password text not null,
	role varchar(16) not null check ( role in ('Admin', 'Staff') ),
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
);

create table tasks (
	id bigint generated always as identity primary key,
	title text not null,
	description text not null,
	status varchar(16) not null check ( status in ('Todo', 'Done') ),
	priority varchar(16) not null check (priority in ('High', 'Low')),
	created_by_id bigint not null references users(id),
	assigned_to_id bigint not null references users(id),
	created_at timestamptz not null default now(),
	updated_at timestamptz not null default now()
)