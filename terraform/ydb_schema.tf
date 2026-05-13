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
