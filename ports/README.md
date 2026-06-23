# Ports of PIPEWATCH-PRO

The primary `audit` command — the OWASP CI/CD Top 10 detectors — ported across
languages so you can drop PIPEWATCH-PRO into any CI runner or ship a single
zero-dependency binary. Every port shares the same rule IDs (`CICD-SEC-01/04/05/06/07`),
the same severity model, the same JSON shape (`{tool, version, summary, findings[]}`),
and the same exit-code contract (non-zero when a critical/high finding exists).

All ports are **passive and offline** — they read pipeline files, they never scan a network.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../pipewatch_pro/` | `pipewatch-pro audit .` | `python -m pytest` |
| Go | `go/` | `cd ports/go && go run . <path>` | `go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- <path>` | `cargo test` |
| Node.js | `javascript/` | `node ports/javascript/index.js <path>` | `cd ports/javascript && node --test` |

Each port supports `--format json` and `--version`. They are built and tested on
every push by [`.github/workflows/ports.yml`](../.github/workflows/ports.yml).

> The Go and Rust ports use the standard library only (no regex crate / no external
> modules), so they compile on a clean toolchain with zero `go get` / `cargo add`.

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see ../CONTRIBUTING.md.
