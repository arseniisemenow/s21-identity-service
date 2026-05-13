variable "yc_cloud_id" {
  description = "Yandex Cloud cloud ID"
  type        = string
}

variable "yc_folder_id" {
  description = "Yandex Cloud folder ID"
  type        = string
}

variable "yc_zone" {
  description = "Yandex Cloud zone"
  type        = string
  default     = "ru-central1-a"
}

variable "log_level" {
  description = "Function log verbosity (info, debug)."
  type        = string
  default     = "info"
}

variable "api_key_enforce" {
  description = "X-Api-Key enforcement mode. \"false\" = dry-run (logs missing/invalid keys but accepts the request). Anything else = enforce (reject with 401). Bootstrap deploys set this to \"false\" until every client has a key; then flip to \"true\"."
  type        = string
  default     = "true"
}
