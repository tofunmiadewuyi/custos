1. custos gen-keys for master key, and hybrid keys
2. set envs for api server
3. custos create-admin to seed the first admin. Password is generated
4. Login to the admin (via API)
5. Create an enrollment token (via API)
6. custosd enroll --control-plane $URL --token $TOKEN
7. Create a public key for the admin
8. Add a grant for the admin to the host. 
9. custosd run (optional flags)
10.Login to the enrolled host with custos-managed credentials. 

