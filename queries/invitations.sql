-- name: CreateInvitation :one
insert into invitations (email, role, token_hash, invited_by, expires_at)
values ($1, $2, $3, $4, $5)
returning *;

-- name: GetInvitationByTokenHash :one
select * from invitations where token_hash = $1;

-- name: MarkInvitationAccepted :exec
update invitations set accepted_at = now() where id = $1;

-- name: ListPendingInvitations :many
select id, email, role, invited_by, expires_at, created_at
from invitations
where accepted_at is null and expires_at > now()
order by created_at desc;

-- name: DeleteInvitation :execrows
delete from invitations where id = $1 and accepted_at is null;

-- name: RefreshInvitationToken :one
update invitations set token_hash = $2, expires_at = $3
where id = $1 and accepted_at is null
returning *;
