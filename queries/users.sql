-- name: GetUserByEmail :one
select * from users where email = $1;

-- name: GetUserByID :one
select * from users where id = $1;

-- name: CreateUser :one
insert into users (email, name, role)
values ($1, $2, $3)
returning *;

-- name: CountActiveAdmins :one
select count(*) from users where role = 'admin' and status = 'active';
