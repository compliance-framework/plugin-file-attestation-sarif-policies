package compliance_framework.sarif_errors

# Policy: ensure a tracked SARIF report is well formed and contains no
# error-level results.

default has_tracked_file := false

risk_templates := [{
  "name": "SARIF report contains unresolved error-level findings",
  "title": "Unresolved Error-Level Findings in SARIF Report",
  "statement": "The SARIF report for the tracked artifact contains at least one result marked at error level. This indicates the producing analysis tool identified one or more serious findings that have not been resolved or formally dispositioned, weakening confidence in the artifact or code under review.",
  "likelihood_hint": "medium",
  "impact_hint": "high",
  "violation_ids": ["sarif_error_result_present"],
  "threat_refs": [],
  "remediation": {
    "title": "Review and resolve error-level SARIF findings",
    "description": "Investigate each error-level result in the SARIF report, correct confirmed issues, and regenerate the report so only accepted warning or note-level outcomes remain.",
    "tasks": [
      { "title": "Review the SARIF results to identify the rules, files, and locations associated with each error-level finding" },
      { "title": "Fix confirmed issues or formally document approved exceptions and adjust the generating tool configuration if the result is not actionable" },
      { "title": "Re-run the producing analysis tool and confirm the updated SARIF report no longer contains error-level results" },
    ]
  }
}]

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

violation[{"id": "sarif_report_unparsable", "remarks": "File isn't a valid SARIF report."}] if {
  has_tracked_file
  input.exists
  not json.unmarshal(input.content)
}

violation[{"id": "sarif_report_invalid", "remarks": "File isn't a valid SARIF report."}] if {
  has_tracked_file
  input.exists
  parsed := json.unmarshal(input.content)
  sarif_is_invalid(parsed)
}
violation[{"id": "sarif_error_result_present", "remarks": "SARIF report contains at least one error result"}] if {
  has_tracked_file
  input.exists
  parsed   := json.unmarshal(input.content)
  sarif_contains_error(parsed)
}

title := "SARIF Report shows no errors"

description := "SARIF Report must show no errors. Warnings and notes are accepted."
