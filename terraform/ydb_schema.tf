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
