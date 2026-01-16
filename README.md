# MatrixRegistration (Rust)

A lightweight Rust rewrite of the Matrix registration helper. It exposes the same `/registration` form endpoint as the original app and talks to Synapse's `/_synapse/admin/v1/register` API using the shared secret flow.

IT IS ONLY API,and all static html and js and css is in `/static`.

## Testing

Set the required environment variables and start the server:

```bash
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

## Run API

```bash
cargo build
nano .env (write your env)
```
And run them.