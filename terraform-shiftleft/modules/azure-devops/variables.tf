variable "org_service_url" {
  description = "Organization service url"
}

variable "personal_access_token" {
  description = "Azure DevOps personal access token"
}

variable "project_name" {
  description = "Azure DevOps project name"
}

variable "sl_org_id" {
  description = "ShiftLeft Organization Id. Visit https://www.shiftleft.io/user/profile to retrieve this value."
}

variable "sl_access_token" {
  description = "ShiftLeft Access token"
}

variable "sl_api_token" {
  description = "ShiftLeft API token"
}

variable "sl_var_group" {
  default     = "shiftleft-token"
  description = "Variable group name for ShiftLeft tokens"
}
