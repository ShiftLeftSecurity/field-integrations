variable "sl_org_id" {
  description = "ShiftLeft Organization Id. Visit https://app.shiftleft.io/user/profile to retrieve this value."
}

variable "sl_access_token" {
  description = "ShiftLeft Access token"
}

variable "sl_api_token" {
  description = "ShiftLeft API token"
}

variable "bitbucket_username" {
  description = "Bitbucket username"
}

variable "bitbucket_app_password" {
  description = "Bitbucket app password with workspace, repositories and pipelines scope"
}

variable "bitbucket_owner" {
  description = "Bitbucket owner. Could be same as username or team name"
}

variable "repos" {
  description = "List of repository to integrate with"
}
