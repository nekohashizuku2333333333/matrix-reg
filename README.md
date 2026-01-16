# MatrixRegistration (Rust)

A lightweight Rust rewrite of the Matrix shared-secret registration helper. It exposes the same `/registration` form endpoint as the original Spring Boot app and talks to Synapse's `/_synapse/admin/v1/register` API using the shared secret flow.

## Running

Set the required environment variables and start the server:

```bash
cd rust-matrixregistration
MATRIX_TOKEN=your-user-facing-token \
MATRIX_SERVER=https://matrix.example.com \
MATRIX_SHARED_SECRET=your-synapse-shared-secret \
BIND_ADDR=0.0.0.0:8080 \
cargo run
```

Env vars:
- `MATRIX_TOKEN`: token users must provide in the form
- `MATRIX_SERVER`: base URL of your homeserver (no trailing slash)
- `MATRIX_SHARED_SECRET`: shared secret from `homeserver.yaml`
- `BIND_ADDR` (optional): host:port to listen on (default `0.0.0.0:8080`)

The `/registration` handler accepts `application/x-www-form-urlencoded` payloads with `username`, `password`, `passwordConfirmation`, and `token` fields and returns a JSON body `{"registrationState":"STATE","username":"name"}`.
