variable "username" {
  description = "Bitbucket username"
}

variable "password" {
  description = "Bitbucket app password"
}

variable "owner" {
  description = "Bitbucket owner or team name"
}

variable "repos" {
  type        = list(string)
  description = "List of repository to integrate with"
}

variable "sl_org_id" {
  description = "ShiftLeft Organization Id. Visit https://app.shiftleft.io/user/profile to retrieve this value."
}

variable "sl_access_token" {
  description = "ShiftLeft Access token"
}

variable "sl_api_token" {
  description = "ShiftLeft API token"
}
