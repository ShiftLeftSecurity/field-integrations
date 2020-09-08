variable "organization" {
  default     = "HooliCorp"
  description = "GitHub organization name"
}

variable "token" {
  description = "GitHub personal access token with repo and workflow scope"
}

variable "poc_repo" {
  description = "A single repository slug for trying out ShiftLeft integration"
}

variable "sl_branch" {
  description = "Branch name to use for ShiftLeft integration."
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

variable "workflow_file" {
  default     = ".github/workflows/shiftleft-inspect.yml"
  description = "Name of the GitHub action workflow file"
}
