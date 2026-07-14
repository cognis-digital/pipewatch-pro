use git2::{Repository, RemoteCallbacks, FetchOptions, ObjectType};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GitScannerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Git error: {0}")]
    Git(String),
    #[error("Repository not found: {0}")]
    NotFound(PathBuf),
    #[error("Clone failed for: {0}, reason: {1}")]
    CloneFailed(PathBuf, String),
}

pub type Result<T> = std::result::Result<T, GitScannerError>;

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub id: String,
    pub author_name: String,
    pub email: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct ScanReport {
    pub repo_url: Option<String>,
    pub commit_count: u64,
    pub total_authors: usize,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub owasp_findings: Vec<OWASPFinding>,
    pub last_commit_date: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug)]
pub struct SuspiciousPattern {
    pub pattern_type: String,
    pub match_count: u32,
    pub examples: Vec<String>,
}

#[derive(Debug)]
pub struct OWASPFinding {
    pub category: String,
    pub severity: SeverityLevel,
    pub description: String,
    pub commit_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityLevel> for &'static str {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Low => "LOW",
            SeverityLevel::Medium => "MEDIUM",
            SeverityLevel::High => "HIGH",
            SeverityLevel::Critical => "CRITICAL",
        }
    }
}

pub struct GitScanner {
    repo: Option<Repository>,
    base_path: PathBuf,
}

impl GitScanner {
    pub fn new(repo_url: &str) -> Result<Self> {
        let repo = Repository::init(&PathBuf::from("/tmp/pipewatch-scan"))?;
        Ok(Self {
            repo: Some(repo),
            base_path: PathBuf::from("/tmp/pipewatch-scan"),
        })
    }

    pub fn open_existing(path: &str) -> Result<Self> {
        let repo = Repository::open(path)?;
        Ok(Self {
            repo: Some(repo),
            base_path: PathBuf::from(path),
        })
    }

    pub fn clone_repository(&mut self, url: &str) -> Result<()> {
        if self.repo.is_some() {
            let _ = self.repo.take();
        }
        
        let repo = Repository::init(&self.base_path)?;
        let mut fetch_opts = FetchOptions::new();
        fetch_opts.remote_callbacks(RemoteCallbacks::new().progress(|_, _, _, remaining| {
            if let Ok(remaining) = remaining {
                eprintln!("Cloning: {} / {}", url, remaining);
            }
            Ok(())
        }));

        repo.fetch(url, Some(&mut fetch_opts), None)?;
        
        // Get the remote URL for reporting
        let url = repo.remote_url()?;
        self.repo = Some(repo);
        self.base_path = repo.workdir().map(|p| p.to_path_buf()).unwrap_or_default();
        
        Ok(())
    }

    pub fn get_commit_info(&self, commit_id: &str) -> Result<CommitInfo> {
        let repo = self.repo.as_ref().ok_or(GitScannerError::Git("No repository open".to_string()))?;
        
        let obj = repo.rev_parse(commit_id)?;
        let (author_name, email, timestamp) = match obj.tree() {
            Ok(tree) => {
                let commit = repo.find_commit(obj.id())?;
                let author = commit.author();
                
                let name = author.name().unwrap_or("Unknown");
                let email = author.email().unwrap_or("");
                let timestamp = chrono::DateTime::from_timestamp(
                    author.timestamp(),
                    0,
                ).ok_or_else(|| GitScannerError::Git(format!("Invalid timestamp: {}", commit_id)))?;
                
                (name.to_string(), email.to_string(), timestamp)
            }
            Err(_) => {
                let commit = repo.find_commit(obj.id())?;
                let author = commit.author();
                (author.name().unwrap_or("Unknown").to_string(), 
                 author.email().unwrap_or("").to_string(),
                 chrono::DateTime::from_timestamp(author.timestamp(), 0).ok_or_else(|| GitScannerError::Git(format!("Invalid timestamp: {}", commit_id))?)
            }
        };

        let message = obj.tree().map(|t| {
            t.iter()
                .filter_map(|e| e.value().path())
                .collect::<Vec<_>>()
                .join(", ")
        }).unwrap_or_else(|| "unknown".to_string());

        Ok(CommitInfo {
            id: commit_id.to_string(),
            author_name,
            email,
            timestamp,
            message,
        })
    }

    pub fn scan_commit_message(&self, message: &str) -> Vec<SuspiciousPattern> {
        let mut patterns = Vec::new();
        
        // OWASP Top 10 related keywords
        let owasp_keywords = [
            ("XSS", "Cross-Site Scripting"),
            ("CSRF", "Cross-Site Request Forgery"),
            ("SQLi", "SQL Injection"),
            ("SSRF", "Server-Side Request Forgery"),
            ("XXE", "XML External Entity"),
            ("IDOR", "Insecure Direct Object Reference"),
            ("RCE", "Remote Code Execution"),
            ("DoS", "Denial of Service"),
        ];

        for (keyword, description) in owasp_keywords {
            if message.contains(keyword) {
                patterns.push(SuspiciousPattern {
                    pattern_type: format!("OWASP_{}", keyword),
                    match_count: 1,
                    examples: vec![message.to_string()],
                });
            }
        }

        // Check for common secrets/keys in commit messages
        let secret_patterns = [
            ("API_KEY", "Potential API key exposure"),
            ("SECRET_", "Potential secret variable"),
            ("PASSWORD=", "Potential password assignment"),
            ("TOKEN=", "Potential token assignment"),
        ];

        for (pattern, description) in secret_patterns {
            if message.contains(pattern) {
                patterns.push(SuspiciousPattern {
                    pattern_type: format!("SECRET_{}", pattern),
                    match_count: 1,
                    examples: vec![message.to_string()],
                });
            }
        }

        // Check for common file paths that might indicate issues
        let path_patterns = [
            ("config/", "Configuration directory"),
            (".env", "Environment variables file"),
            ("secrets/", "Secrets directory"),
            ("credentials/", "Credentials directory"),
        ];

        for (pattern, description) in path_patterns {
            if message.contains(pattern) {
                patterns.push(SuspiciousPattern {
                    pattern_type: format!("PATH_{}", pattern),
                    match_count: 1,
                    examples: vec![message.to_string()],
                });
            }
        }

        // Deduplicate and limit results
        let mut seen = HashSet::new();
        patterns.retain(|p| {
            if !seen.insert(&p.pattern_type) {
                p.match_count += 1;
                false
            } else {
                true
            }
        });

        // Limit examples to prevent huge output
        for pattern in &mut patterns {
            pattern.examples.truncate(3);
        }

        patterns
    }

    pub fn scan_commit_message_paths(&self, message: &str) -> Vec<SuspiciousPattern> {
        let mut patterns = Vec::new();
        
        // Check for common vulnerable file paths in commit messages
        let path_keywords = [
            ("node_modules/", "NPM dependency directory"),
            ("vendor/", "Vendor dependencies"),
            ("gems/", "Ruby gems"),
            ("requirements.txt", "Python requirements"),
            ("package.json", "Node.js package manifest"),
            ("Cargo.toml", "Rust dependencies"),
        ];

        for (path, description) in path_keywords {
            if message.contains(path) {
                patterns.push(SuspiciousPattern {
                    pattern_type: format!("PATH_{}", path),
                    match_count: 1,
                    examples: vec![message.to_string()],
                });
            }
        }

        // Check for common vulnerable functions in commit messages
        let func_keywords = [
            ("eval(", "Potential eval usage"),
            ("exec(", "Potential exec usage"),
            ("system(", "Potential system call"),
            ("shell_exec", "Shell execution"),
            ("cmd.exe", "Windows command execution"),
        ];

        for (func, description) in func_keywords {
            if message.contains(func) {
                patterns.push(SuspiciousPattern {
                    pattern_type: format!("FUNC_{}", func),
                    match_count: 1,
                    examples: vec![message.to_string()],
                });
            }
        }

        // Deduplicate
        let mut seen = HashSet::new();
        patterns.retain(|p| !seen.insert(&p.pattern_type));

        for pattern in &mut patterns {
            pattern.examples.truncate(3);
        }

        patterns
    }

    pub fn get_commit_stats(&self) -> Result<ScanReport> {
        let repo = self.repo.as_ref().ok_or(GitScannerError::Git("No repository open".to_string()))?;
        
        // Get commit count
        let revwalk = repo.rev_walk(revit2::RevWalk::DEFAULT)?;
        let commit_count: u64 = revwalk.count();
        
        // Get unique authors
        let mut author_set = HashSet::new();
        for _ in 0..commit_count.min(100) { // Limit to first 100 commits for performance
            if let Some(commit_id) = revwalk.next() {
                let commit = repo.find_commit(commit_id)?;
                let author_name = commit.author().name();
                author_set.insert(author_name);
            }
        }

        // Get last commit date
        let last_commit_date = if commit_count > 0 {
            revwalk.next()
                .and_then(|id| repo.find_commit(id).ok())
                .map(|c| c.author().timestamp())
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0).ok())
        } else {
            None
        };

        // Scan commit messages for patterns
        let mut suspicious_patterns = Vec::new();
        let mut owasp_findings = Vec::new();

        for _ in 0..commit_count.min(50) {
            if let Some(commit_id) = revwalk.next() {
                if let Ok(commit) = repo.find_commit(commit_id) {
                    let message = commit.message().unwrap_or("no message");
                    
                    // Scan for OWASP patterns
                    let owasp_patterns = self.scan_commit_message(message);
                    for pattern in &owasp_patterns {
                        suspicious_patterns.push(pattern.clone());
                        
                        if pattern.pattern_type.starts_with("OWASP_") {
                            owasp_findings.push(OWASPFinding {
                                category: "OWASP Top 10".to_string(),
                                severity: SeverityLevel::Medium,
                                description: format!("Found OWASP pattern in commit {}", commit_id),
                                commit_id: Some(commit_id.to_string()),
                            });
                        }
                    }

                    // Scan for path patterns
                    let path_patterns = self.scan_commit_message_paths(message);
                    suspicious_patterns.extend(path_patterns);
                }
            }
        }

        Ok(ScanReport {
            repo_url: repo.remote_url().ok(),
            commit_count,
            total_authors: author_set.len(),
            suspicious_patterns,
            owasp_findings,
            last_commit_date,
        })
    }

    pub fn get_file_tree(&self) -> Result<Vec<String>> {
        let repo = self.repo.as_ref().ok_or(GitScannerError::Git("No repository open".to_string()))?;
        
        // Get the latest commit's tree
        let obj = repo.head()?.peel(ObjectType::Tree)?;
        let tree = obj.tree()?;
        
        let mut files: Vec<_> = tree.iter()
            .map(|e| e.value().path())
            .collect();
        
        // Sort for consistent output
        files.sort();
        
        Ok(files)
    }

    pub fn get_branches(&self) -> Result<Vec<String>> {
        let repo = self.repo.as_ref().ok_or(GitScannerError::Git("No repository open".to_string()))?;
        
        let mut branches: Vec<_> = repo.branches(None, git2::BranchTarget::Local)?
            .filter_map(|b| b.ok())
            .map(|b| b.name().unwrap_or("").to_string())
            .collect();
        
        // Sort and filter out HEAD references
        branches.sort();
        branches.retain(|s| !s.starts_with("HEAD"));
        
        Ok(branches)
    }

    pub fn get_tags(&self) -> Result<Vec<String>> {
        let repo = self.repo.as_ref().ok_or(GitScannerError::Git("No repository open".to_string()))?;
        
        let mut tags: Vec<_> = repo.tags()?
            .filter_map(|t| t.ok())
            .map(|t| t.name().unwrap_or("").to_string())
            .collect();
        
        // Sort and filter out annotated vs lightweight duplicates
        tags.sort();
        tags.dedup();
        
        Ok(tags)
    }

    pub fn generate_report(&self, report: &ScanReport) -> Result<String> {
        let mut output = String::new();
        
        output.push_str("=== Pipewatch Pro Git Scanner Report ===\n\n");
        
        // Summary section
        output.push_str(&format!("Summary:\n"));
        output.push_str(&format!("  Repository: {:?}\n", report.repo_url.as_deref().unwrap_or("Unknown")));
        output.push_str(&format!("  Total Commits: {}\n", report.commit_count));
        output.push_str(&format!("  Unique Authors: {}\n", report.total_authors));
        
        if let Some(last_date) = report.last_commit_date {
            output.push_str(&format!("  Last Commit: {}\n", last_date.format("%Y-%m-%d %H:%M:%S UTC")));
        } else {
            output.push_str("  Last Commit: Unknown\n");
        }
        
        // OWASP Findings
        if !report.owasp_findings.is_empty() {
            output.push_str("\n--- OWASP Top 10 Findings ---\n");
            
            let mut by_severity: HashMap<SeverityLevel, Vec<_>> = HashMap::new();
            for finding in &report.owasp_findings {
                by_severity.entry(finding.severity).or_insert_with(Vec::new).push(finding);
            }
            
            for (severity, findings) in &by_severity {
                let severity_str: String = (*severity).into();
                output.push_str(&format!("\n  [{}] {}\n", severity_str, findings.len()));
                
                for finding in findings.iter().take(5) {
                    output.push_str(&format!("    - {} (Commit: {:?})\n", 
                        &finding.description[..100],
                        finding.commit_id.as_deref(),
                    ));
                }
            }
        } else {
            output.push_str("\n--- OWASP Top 10 Findings ---\n");
            output.push_str("  No OWASP patterns detected\n");
        }
        
        // Suspicious Patterns
        if !report.suspicious_patterns.is_empty() {
            output.push_str(&format!("\n--- Suspicious Patterns ({}) ---\n", report.suspicious_patterns.len()));
            
            let mut by_type: HashMap<String, &SuspiciousPattern> = HashMap::new();
            for pattern in &report.suspicious_patterns {
                by_type.entry(pattern.pattern_type.clone()).or_insert(pattern);
            }
            
            for (type_name, pattern) in &by_type {
                output.push_str(&format!("  [{}] - {}\n", type_name, &pattern.description));