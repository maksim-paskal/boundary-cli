# Boundary Helper
## Requirements
Install boundary CLI Binnary
```
https://releases.hashicorp.com/boundary
```
Edit your environment
```bash
nano ~/.zshrc

export BOUNDARY_ADDR=https://boundary-url.domain
export BOUNDARY_SCOPE_ID=p_12345678
export BOUNDARY_AUTH_METHOD_ID=amoidc_12345678
```
Install latest helper