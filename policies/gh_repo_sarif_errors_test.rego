package compliance_framework.sarif_errors

# test sarif_contains_error when there is an error-level result
test_sarif_contains_error_true if {
  sarif := {
    "runs": [
      {
        "results": [
          {"level": "error"},
        ],
      },
    ],
  }

  sarif_contains_error(sarif)
}

# test sarif_contains_error fails as invalid SARIF type
test_sarif_fail_if_not_a_sarif if {
  inp := {
    "path":   "main.go",
    "exists": true,
    "content": "not a sarif",
  }

  violation[v] with input as inp
  v.remarks == "File isn't a valid SARIF report."
}

# test sarif_contains_error fails as invalid SARIF type
test_sarif_fail_if_json_not_a_sarif if {
  sarif := {
    "not": {
      "a": {
        "sarif":  "here"
      }
    }
  }
  inp := {
    "path":   "main.go",
    "exists": true,
    "content": json.marshal(sarif),
  }

  violation[v] with input as inp
  v.remarks == "File isn't a valid SARIF report."
}

# test sarif_contains_error fails as invalid SARIF type
test_sarif_fail_if_json_not_a_sarif_results_missing if {
  sarif := {
    "runs": [{
      "foo": "bar"
    }]
  }
  sarif_is_invalid(sarif)
}

# test sarif_contains_error fails as invalid SARIF type
test_sarif_fail_if_json_not_a_sarif_results_missing if {
  sarif := {
    "runs": [{
      "results": [{
              "foo": "bar"
      }]
    }]
  }
  sarif_is_invalid(sarif)
}

# test for a valid sarif
test_sarif_is_valid if {
  sarif := {
    "runs": [{
      "results": [{
              "level": "very levely"
      }]
    }]
  }
  not sarif_is_invalid(sarif)
}


# test sarif_contains_error when there is an error-level in separate runs
test_sarif_contains_error_true if {
  sarif := {
    "runs": [
      {
        "results": [
          {"level": "warning"},
          {"level": "note"},
        ],
      },
      {
        "results": [
          {"level": "warning"},
          {"level": "error"},
        ],
      },
    ],
  }

  sarif_contains_error(sarif)
}

# test sarif_contains_error when there is no results
test_sarif_contains_error_true if {
  sarif := {
    "runs": [
      {
        "results": [],
      },
      {
        "results": [],
      },
      {
        "results": [],
      },
    ],
  }
  not sarif_contains_error(sarif)
}

# test violation fires when file exists and SARIF has an error
test_violation_when_error_and_file_exists if {
  sarif := {
    "runs": [
      {
        "results": [
          {"level": "error"},
        ],
      },
    ],
  }

  inp := {
    "path":   "main.go",
    "exists": true,
    "content": json.marshal(sarif),
  }

  violation[v] with input as inp
  v.remarks == "SARIF report contains at least one error result"
}

# test no violation when SARIF has no error
test_no_violation_when_no_error if {
  sarif := {
    "runs": [
      {
        "results": [
          {"level": "warning"},
        ],
      },
    ],
  }

  inp := {
    "path":   "main.go",
    "exists": true,
    "content": json.marshal(sarif),
  }
  
  violations := [v | violation[v] with input as inp]
  count(violations) == 0
}