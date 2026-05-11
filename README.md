# ttbot-identity-service

HTTP API for the ttbot identity service. Owns the canonical
`(telegram_id ↔ S21 nickname)` mapping shared across all S21-related
Telegram bots.

## Endpoints

All endpoints require `X-S21-Token: <login>:<password>` (validated against S21).

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/users/by_telegram/{tid}` | — | `User` or 404 |
| `POST` | `/users/lookup_telegram_batch` | `{telegram_ids:[...]}` | `{users:[...]}` |
| `GET` | `/users/by_nickname/{nick}` | — | `{users:[...]}` (Q4: may be ≥1) |
| `PUT` | `/users/by_telegram/{tid}` | `{nickname}` | `User` |
| `DELETE` | `/users/by_telegram/{tid}` | — | 204 |
| `GET` | `/health` | — | `ok` |

## Architecture

- Yandex Cloud Function behind API Gateway.
- YDB serverless: `identity_users`, `s21_nickname_cache`.
- On a `PUT` with an unknown nickname, the service calls S21
  `LookupByLogin` once and caches the result for future writes.

## Local

```sh
go test ./...
```

## Deploy

```sh
cd terraform
terraform plan
terraform apply
```

Outputs the service URL — use it as `IDENTITY_SERVICE_URL` in callers (ttbot,
identity bot).
