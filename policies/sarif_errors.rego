package compliance_framework.sarif_errors

# Policy: ensure the tracked critical file exists in the repository.

default has_tracked_file := false

has_tracked_file if {
  input.path != ""
}

sarif_contains_error(parsed) if {
  some i
  parsed.runs[i].results

  some j
  result := parsed.runs[i].results[j]

  result.level == "error"
}

sarif_is_invalid(parsed) if {
  # 1. runs is missing
  not parsed.runs
}

sarif_is_invalid(parsed) if {
  # 2. at least one run has no results field
  some i
  parsed.runs[i]
  not parsed.runs[i].results
}

sarif_is_invalid(parsed) if {
  # 3. results exist, but some result entry has no level
  some i
  parsed.runs[i]
  parsed.runs[i].results

  some j
  parsed.runs[i].results[j]
  not parsed.runs[i].results[j].level
}

violation[{"remarks": "File isn't a valid SARIF report."}] if {
  has_tracked_file
  input.exists
  not json.unmarshal(input.content)
}

violation[{"remarks": "File isn't a valid SARIF report."}] if {
  has_tracked_file
  input.exists
  parsed := json.unmarshal(input.content)
  sarif_is_invalid(parsed)
}
violation[{"remarks": "SARIF report contains at least one error result"}] if {
  has_tracked_file
  input.exists
  parsed   := json.unmarshal(input.content)
  sarif_contains_error(parsed)
}

title := "SARIF Report shows no errors"

description := "SARIF Report must show no errors. Warnings and notes are accepted."
