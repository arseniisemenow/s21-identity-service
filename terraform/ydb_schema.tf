resource "yandex_ydb_database_serverless" "db" {
  name                = "identity-service-db"
  deletion_protection = false

  labels = {
    project = "identity"
  }
}

locals {
  ydb_conn = yandex_ydb_database_serverless.db.ydb_full_endpoint
}

# identity_users — (telegram_id ↔ S21 nickname) bindings + cached S21 profile.
resource "yandex_ydb_table" "identity_users" {
  path              = "identity_users"
  connection_string = local.ydb_conn

  column {
    name     = "telegram_id"
    type     = "Uint64"
    not_null = true
  }
  column {
    name     = "nickname"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "campus_id"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "campus_name"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "coalition_name"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "created_at"
    type     = "Timestamp"
    not_null = true
  }
  column {
    name     = "updated_at"
    type     = "Timestamp"
    not_null = true
  }

  primary_key = ["telegram_id"]
}

# api_keys — issued API keys for the perimeter check. Stored as sha256 of the
# plaintext only; plaintext is shown once at creation and never recoverable
# afterwards. revoked_at = NULL means active. Combined with X-S21-Token on
# every request (defense in depth).
resource "yandex_ydb_table" "api_keys" {
  path              = "api_keys"
  connection_string = local.ydb_conn

  column {
    name     = "key_hash"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "name"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "scopes"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "created_at"
    type     = "Timestamp"
    not_null = true
  }
  column {
    name     = "revoked_at"
    type     = "Timestamp"
    not_null = false
  }
  column {
    name     = "created_by_telegram_id"
    type     = "Uint64"
    not_null = false
  }

  primary_key = ["key_hash"]
}

# s21_token_cache — durable memoization of "this X-S21-Token (hashed) has
# been validated against S21 and resolved to this login, valid until
# expires_at". Read on every inbound request before the in-memory LRU
# falls back to a live S21 round-trip; written after a successful round-
# trip. token_hash is base64(sha256("login:password")) — the plaintext
# creds are NEVER persisted, only the hash. Failures are never cached.
# TTL is 30 days, enforced by the Go layer reading expires_at.
resource "yandex_ydb_table" "s21_token_cache" {
  path              = "s21_token_cache"
  connection_string = local.ydb_conn

  column {
    name     = "token_hash"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "login"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "expires_at"
    type     = "Timestamp"
    not_null = true
  }

  primary_key = ["token_hash"]
}

# s21_nickname_cache — lazy cache of "this S21 login has been validated".
resource "yandex_ydb_table" "s21_nickname_cache" {
  path              = "s21_nickname_cache"
  connection_string = local.ydb_conn

  column {
    name     = "nickname"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "campus_id"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "campus_name"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "coalition_name"
    type     = "Utf8"
    not_null = true
  }
  column {
    name     = "cached_at"
    type     = "Timestamp"
    not_null = true
  }

  primary_key = ["nickname"]
}
