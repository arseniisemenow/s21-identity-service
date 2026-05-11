output "ydb_endpoint" {
  description = "YDB endpoint"
  value       = yandex_ydb_database_serverless.db.ydb_full_endpoint
}

output "function_id" {
  description = "Cloud Function ID"
  value       = yandex_function.identity_service.id
}

output "gateway_id" {
  description = "API Gateway ID"
  value       = yandex_api_gateway.gateway.id
}

output "service_url" {
  description = "Public URL of the identity service"
  value       = "https://${yandex_api_gateway.gateway.domain}"
}
