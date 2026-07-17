api server / control plane
- authentication: login, invite, reset-password
- password mgmt: create password, it is encrypted at rest, logged each time it is accessed
- permissions: you can give someone access to a password, or a resource group. and also revoke that access.
- resource-group: just a convenient way to bucket access. you can make a project a resource and put all associated passwords/servers in it
- servers: the daemon would be installed on each server we need to manage. granting permission to the server (or a resource group containing it) allows someone with a registered key access the server.
- postgres backed

cli / daemon
- uses AuthorizedKeyCommand 
- sshd checks with daemon before allowing access
- maintains a local-cache or people who should have access
- maintains a connection to the control plane, for granting instant access + instant revocations


other notes
There would be 2 types of users, admins and others, admins can do everything, create resource group, create credential, revoke, etc

