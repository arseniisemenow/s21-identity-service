terraform {
  required_version = ">= 1.0"

  required_providers {
    yandex = {
      source  = "yandex-cloud/yandex"
      version = "~> 0.113.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

data "external" "iam_token" {
  program = ["bash", "-c", "echo '{\"token\":\"'$(yc iam create-token 2>/dev/null)'\"}'"]
}

provider "yandex" {
  cloud_id  = var.yc_cloud_id
  folder_id = var.yc_folder_id
  zone      = var.yc_zone
  token     = data.external.iam_token.result["token"]
}

# Service account: function runs as this SA, gateway integration uses it too.
resource "yandex_iam_service_account" "fn_sa" {
  name        = "identity-service-fn-sa"
  description = "Service account for the identity-service Cloud Function"
}

resource "yandex_resourcemanager_folder_iam_member" "fn_sa_ydb_editor" {
  folder_id = var.yc_folder_id
  role      = "ydb.editor"
  member    = "serviceAccount:${yandex_iam_service_account.fn_sa.id}"
}

# Function source bundle.
data "archive_file" "function" {
  type        = "zip"
  source_dir  = "${path.module}/function"
  output_path = "${path.module}/function.zip"
  excludes    = ["function", "function.zip", ".gitkeep"]
}

resource "yandex_function" "identity_service" {
  name               = "identity-service-api"
  description        = "Identity service HTTP API"
  user_hash          = data.archive_file.function.output_base64sha256
  runtime            = "golang123"
  entrypoint         = "handler.Handler"
  memory             = 256
  execution_timeout  = 30
  service_account_id = yandex_iam_service_account.fn_sa.id

  content {
    zip_filename = data.archive_file.function.output_path
  }

  environment = {
    YDB_ENDPOINT      = yandex_ydb_database_serverless.db.ydb_full_endpoint
    YDB_AUTH_METADATA = "true"
    LOG_LEVEL         = var.log_level
    # API_KEY_ENFORCE: "false" puts the X-Api-Key check into dry-run mode
    # (logs but accepts). Any other value (incl. unset) → enforce. Operator
    # sets this to "false" for the bootstrap deploy, then to "true" once
    # every client has its API key.
    API_KEY_ENFORCE = var.api_key_enforce
  }
}

resource "yandex_function_iam_binding" "public_invoker" {
  function_id = yandex_function.identity_service.id
  role        = "serverless.functions.invoker"
  members     = ["system:allUsers"]
}

resource "yandex_api_gateway" "gateway" {
  name        = "identity-service-gateway"
  description = "API Gateway fronting the identity service"
  labels = {
    bot = "identity"
  }

  spec = <<-EOF
    openapi: "3.0.0"
    info:
      title: "Identity Service"
      version: "1.0"
    x-yc-apigateway:
      cors:
        origin: "*"
        methods: "GET, POST, PUT, DELETE, OPTIONS"
        allowedHeaders: "X-S21-Token, Content-Type"
    paths:
      /{path+}:
        x-yc-apigateway-any-method:
          parameters:
            - description: "path"
              in: path
              name: path
              required: true
              schema:
                type: string
          x-yc-apigateway-integration:
            type: cloud_functions
            function_id: ${yandex_function.identity_service.id}
            service_account_id: ${yandex_iam_service_account.fn_sa.id}
  EOF
}
