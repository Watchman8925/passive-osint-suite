package main

__rego_metadata__ := {
  "id": "compose.policy.osint",
  "title": "Compose compliance for osint-suite",
  "version": "0.1.0",
  "description": "Ensures the osint-suite service adheres to minimal security best practices.",
}

deny[msg] {
  not input.services["osint-suite"].user
  msg := "compose: osint-suite must set non-root user"
}

deny[msg] {
  input.services["osint-suite"].privileged == true
  msg := "compose: osint-suite must not run privileged"
}

deny[msg] {
  some i
  input.services["osint-suite"].cap_add[i]
  msg := sprintf("compose: osint-suite must not add capabilities (found %v)", [input.services["osint-suite"].cap_add])
}

deny[msg] {
  not input.services["osint-suite"].restart
  msg := "compose: osint-suite should set a restart policy"
}
