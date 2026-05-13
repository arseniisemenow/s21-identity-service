# ttbot-identity-service

HTTP API for the ttbot identity service. Owns the canonical
`(telegram_id ↔ S21 nickname)` mapping shared across all S21-related
Telegram bots.

## Endpoints

Every endpoint requires **both** of the following on every request, and
the connection must be HTTPS (the service rejects plain HTTP at the gate):

- `X-Api-Key: <key>` — issued via the admin CLI; the service stores only
  sha256 of the plaintext.
- `X-S21-Token: <login>:<password>` — validated against S21 (with cache
  acceleration).

The two checks compose: the API key is the perimeter ("you are an
authorised client"), the S21 token is the actor ("you are this specific
S21 admin"). Both are required even on reads.

### Endpoints

| Method | Path | Required scope | Body | Returns |
|---|---|---|---|---|
| `GET`    | `/users/by_telegram/{tid}`      | `read`  | —                          | `User` or 404 |
| `POST`   | `/users/lookup_telegram_batch`  | `read`  | `{telegram_ids:[...]}`     | `{users:[...]}` |
| `GET`    | `/users/by_nickname/{nick}`     | `read`  | —                          | `{users:[...]}` (Q4: may be ≥1) |
| `PUT`    | `/users/by_telegram/{tid}`      | `write` | `{nickname}`               | `User` |
| `DELETE` | `/users/by_telegram/{tid}`      | `write` | —                          | 204 |
| `POST`   | `/admin/keys`                   | `write` | `{name, scopes, created_by_telegram_id?}` | `CreateKeyResponse` (plaintext shown ONCE) |
| `DELETE` | `/admin/keys/{name}?created_by={tid}` | `write` | —                    | 204 |
| `GET`    | `/admin/keys`                   | `write` | —                          | `{keys:[...]}` (no plaintext, no hash) |
| `GET`    | `/health`                       | none    | —                          | `ok` |

Notes:

- Scopes are stored canonically: `"read"` or `"read,write"`. Write implies
  read. Posting `"write"` alone normalises to `"read,write"`.
- One non-revoked key per `created_by_telegram_id` (when non-zero). A
  second mint with the same owner returns 409 `creator_has_key`.
- Names are unique among non-revoked rows. Reuse is allowed after revoke.
- Revoke is a soft delete (`revoked_at IS NOT NULL`); the row stays in
  the table for the audit trail.

## Architecture

- Yandex Cloud Function behind API Gateway (TLS termination at the gateway;
  the service trusts `X-Forwarded-Proto: https`).
- YDB serverless: `identity_users`, `s21_nickname_cache`, `api_keys`.
- On a `PUT` with an unknown nickname, the service calls S21
  `LookupByLogin` once and caches the result for future writes.

## Admin CLI

`cmd/admin/` ships a small CLI binary (`ttbot-identity-admin`) for managing
API keys. It connects directly to YDB using a `yc iam create-token`, so the
operator doesn't need an existing API key to bootstrap the system.

```sh
# Authenticate yc once:
yc init

# Mint identity-bot's own write-scope key:
YDB_ENDPOINT="<from terraform output -raw ydb_endpoint>" \
  go run ./cmd/admin create-key --name identity-bot-prod --scopes write

# Mint ttbot's read-only key:
go run ./cmd/admin create-key --name ttbot-prod --scopes read

# Tabulate (active only by default; --all includes revoked):
go run ./cmd/admin list-keys
go run ./cmd/admin list-keys --all

# Revoke:
go run ./cmd/admin revoke-key --name some-old-key
```

`create-key` prints the plaintext **once** with a red one-shot banner.
Copy it immediately into the receiving service's env (e.g. into the
relevant `terraform.tfvars`), then redeploy.

## Bootstrap

The first deploy with the new auth model needs a brief overlap window so
existing clients (which don't yet have keys) keep working. Sequence:

1. **Deploy identity-service in dry-run mode**: `terraform apply` with
   `api_key_enforce = "false"` set in `terraform.tfvars`. The new
   `api_keys` table is created and the middleware logs warnings but
   accepts requests without a key.
2. **Mint keys via the CLI**: one for identity-bot (write), one for
   ttbot (read). Paste each plaintext into the respective service's
   `terraform.tfvars` (`identity_service_api_key`, `identity_api_key`).
3. **Redeploy identity-bot and ttbot** so both start sending
   `X-Api-Key` on every call.
4. **Flip to enforcing**: set `api_key_enforce = "true"` and `terraform
   apply` identity-service again. From this point any request lacking a
   valid key gets 401.

## Local development

```sh
go test ./...
```

## Deploy

```sh
cd terraform
terraform plan
terraform apply
```

Outputs the service URL — use it as `IDENTITY_SERVICE_URL` in callers
(ttbot, identity-bot).
