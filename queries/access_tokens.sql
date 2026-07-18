-- name: CreateAccessToken :one
insert into access_tokens (session_id, token_hash, expires_at)
values ($1, $2, $3)
returning *;

-- name: GetAccessContext :one
select s.id as session_id, s.client_public_key, u.id as user_id, u.role, u.status
from access_tokens at
join sessions s on s.id = at.session_id
join users u on u.id = s.user_id
where at.token_hash = $1
  and at.expires_at > now()
  and s.revoked_at is null
  and s.expires_at > now();
