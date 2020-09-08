variable "sl_org_id" {
  description = "ShiftLeft Organization Id. Visit https://www.shiftleft.io/user/profile to retrieve this value."
}

variable "sl_access_token" {
  description = "ShiftLeft Access token"
}

variable "sl_api_token" {
  description = "ShiftLeft API token"
}

variable "sl_branch" {
  default     = "feature/shiftleft"
  description = "Branch name to use for ShiftLeft integration."
}

variable "poc_repo" {
  description = "A single repository slug for trying out ShiftLeft integration"
  default     = "HooliCorp/java-example"
}
