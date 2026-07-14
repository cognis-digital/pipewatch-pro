use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a resolved dependency with its metadata
#[derive(Debug, Clone)]
pub struct ResolvedDependency {
    pub name: String,
    pub version: semver::Version,
    pub source: DependencySource,
    pub resolved_at: SystemTime,
}

/// Source of the dependency declaration
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DependencySource {
    CargoToml,
    NpmPkgJson,
    PipRequirements,
    GitHubActions,
    GitLabCi,
    Unknown,
}

impl Default for DependencySource {
    fn default() -> Self {
        DependencySource::Unknown
    }
}

/// Represents a CI/CD pipeline configuration
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    pub name: String,
    pub platform: PlatformType,
    pub stages: Vec<String>,
    pub jobs: Vec<JobDefinition>,
    pub dependencies: Vec<DependencyDeclaration>,
    pub resolved_at: SystemTime,
}

#[derive(Debug, Clone)]
pub enum PlatformType {
    GitHubActions,
    GitLabCi,
    AzureDevOps,
    Jenkins,
    CircleCI,
    Unknown,
}

impl Default for PlatformType {
    fn default() -> Self {
        PlatformType::Unknown
    }
}

/// A job definition within a pipeline
#[derive(Debug, Clone)]
pub struct JobDefinition {
    pub name: String,
    pub platform: Option<String>,
    pub steps: Vec<StepDefinition>,
    pub env_vars: HashMap<String, String>,
}

/// A step within a CI/CD job
#[derive(Debug, Clone)]
pub struct StepDefinition {
    pub run: Option<String>, // shell command
    pub name: Option<String>,
    pub uses: Option<String>, // reusable workflow reference
    pub with: HashMap<String, String>,
}

/// A dependency declaration found in the pipeline
#[derive(Debug, Clone)]
pub struct DependencyDeclaration {
    pub package_name: String,
    pub version_constraint: String,
    pub manager: DependencySource,
    pub context: Option<String>, // e.g., "build", "test"
}

/// Audit result for a single dependency check
#[derive(Debug, Clone)]
pub struct DependencyCheckResult {
    pub name: String,
    pub version: semver::Version,
    pub status: CheckStatus,
    pub vulnerabilities: Vec<Vulnerability>,
    pub warnings: Vec<String>,
}

/// Status of a dependency check
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CheckStatus {
    Safe,
    Vulnerable,
    Deprecated,
    Unknown,
}

impl Default for CheckStatus {
    fn default() -> Self {
        CheckStatus::Unknown
    }
}

/// A known vulnerability in a dependency
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub severity: SeverityLevel,
    pub cve_id: Option<String>,
    pub affected_versions: Vec<semver::VersionRange>,
    pub fixed_in: semver::Version,
}

/// Severity level of a vulnerability
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for SeverityLevel {
    fn default() -> Self {
        SeverityLevel::Medium
    }
}

/// OWASP CI/CD Top 10 vulnerability patterns (simulated database)
pub fn get_owasp_patterns() -> Vec<OWASPPattern> {
    vec![
        // Pattern: Hardcoded credentials in pipeline scripts
        OWASPPattern {
            id: "CI-2024-001".to_string(),
            name: "Hardcoded Credentials",
            description: "Credentials embedded directly in CI/CD scripts or environment variables",
            severity: SeverityLevel::High,
            patterns: vec![
                r#"password\s*=\s*['"]?\w+['"]?#i,
                r#"secret\s*=\s*['"]?\w+['"]?#i,
                r#"api_key\s*=\s*['"]?\w+['"]?#i,
                r#"token\s*=\s*['"]?\w+['"]?#i,
            ],
        },
        // Pattern: Insecure dependency resolution
        OWASPPattern {
            id: "CI-2024-002".to_string(),
            name: "Insecure Dependency Resolution",
            description: "Using 'latest' or '*' without pinning versions",
            severity: SeverityLevel::Medium,
            patterns: vec![
                r#"version\s*=\s*\*#i,
                r#"version\s*=\s*latest#i,
                r#"~> 0.1.#i,
            ],
        },
        // Pattern: Unverified external artifacts
        OWASPPattern {
            id: "CI-2024-003".to_string(),
            name: "Unverified External Artifacts",
            description: "Downloading artifacts from untrusted sources",
            severity: SeverityLevel::High,
            patterns: vec![
                r#"curl\s+.*\-\s*#i,
                r#"wget\s+.*\-\s*#i,
                r#"git\s+clone\s+https://[^"]+#i,
            ],
        },
    ]
}

/// OWASP CI/CD Top 10 pattern definition
#[derive(Debug, Clone)]
pub struct OWASPPattern {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: SeverityLevel,
    pub patterns: Vec<String>,
}

/// Main dependency resolver for CI/CD pipelines
pub struct DepResolver<'a> {
    config_dir: &'a Path,
    known_dependencies: HashMap<String, ResolvedDependency>,
    owasp_patterns: Vec<OWASPPattern>,
}

impl<'a> DepResolver<'a> {
    /// Create a new resolver with optional configuration directory
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        let config_dir = config_dir.into();
        
        // Load known dependencies from cache (simulated)
        let mut known_deps = HashMap::new();
        if let Ok(content) = fs::read_to_string(
            config_dir.join("known-deps.json")
        ) {
            if !content.is_empty() {
                // Simulate loading cached data
                known_deps.insert("serde".to_string(), ResolvedDependency {
                    name: "serde".to_string(),
                    version: semver::Version::parse("1.0.193").unwrap(),
                    source: DependencySource::CargoToml,
                    resolved_at: SystemTime::now(),
                });
            }
        }

        // Load OWASP patterns
        let owasp_patterns = get_owasp_patterns();

        DepResolver {
            config_dir,
            known_dependencies: known_deps,
            owasp_patterns,
        }
    }

    /// Scan the repository for CI/CD configurations and dependencies
    pub fn scan(&mut self) -> Result<PipelineScanResult, Error> {
        let mut pipelines = Vec::new();
        
        // Find GitHub Actions workflows
        if let Ok(workflows) = fs::read_dir(
            self.config_dir.join(".github/workflows")
        ) {
            for workflow in workflows.flatten() {
                if let Some(name) = workflow.file_name().to_str() {
                    if name.ends_with(".yml") || name.ends_with(".yaml") {
                        match self.parse_github_workflow(&workflow.path()) {
                            Ok(pipeline) => pipelines.push(pipeline),
                            Err(e) => eprintln!("Warning: Failed to parse {}: {}", 
                                workflow.path().display(), e),
                        }
                    }
                }
            }
        }

        // Find GitLab CI configuration
        if let Ok(ci_file) = fs::read_to_string(
            self.config_dir.join(".gitlab-ci.yml")
        ) {
            match self.parse_gitlab_ci(&ci_file) {
                Ok(pipeline) => pipelines.push(pipeline),
                Err(e) => eprintln!("Warning: Failed to parse .gitlab-ci.yml: {}", e),
            }
        }

        // Find Cargo.toml for Rust dependencies
        if let Ok(cargo_content) = fs::read_to_string(
            self.config_dir.join("Cargo.toml")
        ) {
            match self.parse_cargo_toml(&cargo_content) {
                Some(pipeline) => pipelines.push(pipeline),
                None => {}
            }
        }

        Ok(PipelineScanResult {
            pipelines,
            scan_time: SystemTime::now(),
        })
    }

    /// Parse a GitHub Actions workflow file
    fn parse_github_workflow(&self, path: &Path) -> Result<PipelineConfig, Error> {
        let content = fs::read_to_string(path)?;
        
        // Simple YAML parsing for demonstration
        let name = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unnamed");

        let platform = PlatformType::GitHubActions;
        
        // Extract stages and jobs from content (simplified)
        let stages: Vec<String> = content.lines()
            .filter(|line| line.trim().starts_with("  - "))
            .map(|l| l.trim().strip_prefix("  - ").unwrap_or("").to_string())
            .collect();

        // Extract jobs section
        let mut jobs = Vec::new();
        if let Some(start) = content.find("jobs:") {
            let end = content[start + 5..].find('}').map(|i| start + 5 + i).unwrap_or(content.len());
            let jobs_content = &content[start + 5..end];
            
            // Parse individual jobs (simplified)
            if let Some(job_start) = jobs_content.find("name:") {
                while job_start < end {
                    let name_end = jobs_content[job_start..].find('\n').map(|i| job_start + i).unwrap_or(end);
                    let name_line = &jobs_content[job_start..name_end];
                    
                    if let Some(job_name) = name_line.strip_prefix("  name:") {
                        let name = job_name.trim().to_string();
                        
                        // Extract steps
                        let mut steps = Vec::new();
                        if let Some(step_start) = jobs_content.find("steps:") {
                            let step_end = jobs_content[step_start..].find('}').map(|i| step_start + i).unwrap_or(end);
                            let steps_content = &jobs_content[step_start..step_end];
                            
                            // Parse steps (simplified)
                            for line in steps_content.lines() {
                                if line.trim().starts_with("      - run:") || 
                                   line.trim().starts_with("      - uses:") {
                                    let cmd = line.strip_prefix("      - ").unwrap_or("");
                                    let step_name = cmd.split(':').next().unwrap_or("").trim();
                                    
                                    steps.push(StepDefinition {
                                        run: Some(cmd.to_string()),
                                        name: Some(step_name.to_string()),
                                        uses: None,
                                        with: HashMap::new(),
                                    });
                                }
                            }
                        }

                        jobs.push(JobDefinition {
                            name,
                            platform: None,
                            steps,
                            env_vars: HashMap::new(),
                        });
                    }
                    
                    job_start = name_end;
                }
            }
        }

        // Extract dependencies from environment or uses statements
        let mut dependencies = Vec::new();
        
        for line in content.lines() {
            if line.contains("uses:") || line.contains("with:") {
                continue; // Skip workflow references, handled separately
            }
            
            // Look for common dependency patterns
            if line.contains("cargo:") || line.contains("npm:") || 
               line.contains("pip:") || line.contains("mvn:") {
                
                let manager = if line.contains("cargo:") {
                    DependencySource::CargoToml
                } else if line.contains("npm:") {
                    DependencySource::NpmPkgJson
                } else if line.contains("pip:") {
                    DependencySource::PipRequirements
                } else if line.contains("mvn:") {
                    DependencySource::Unknown // Maven not fully implemented
                } else {
                    DependencySource::GitHubActions
                };

                let (name, version) = Self::extract_dependency_info(line);
                
                dependencies.push(DependencyDeclaration {
                    package_name: name,
                    version_constraint: version,
                    manager,
                    context: Some("build".to_string()),
                });
            }
        }

        Ok(PipelineConfig {
            name: format!("github_{}", name),
            platform,
            stages,
            jobs,
            dependencies,
            resolved_at: SystemTime::now(),
        })
    }

    /// Parse a GitLab CI configuration file
    fn parse_gitlab_ci(&self, content: &str) -> Result<PipelineConfig, Error> {
        let name = "gitlab_default";
        
        // Extract stages
        let mut stages = Vec::new();
        if let Some(start) = content.find("stages:") {
            let end = content[start + 7..].find('}').map(|i| start + 7 + i).unwrap_or(content.len());
            let stages_content = &content[start + 7..end];
            
            for line in stages_content.lines() {
                if line.trim().starts_with("- ") {
                    stages.push(line.trim().strip_prefix("- ").unwrap_or("").to_string());
                }
            }
        }

        // Extract jobs
        let mut jobs = Vec::new();
        
        if let Some(job_start) = content.find("before_script:") {
            // Parse before_script for dependencies
            let script_content = &content[job_start..];
            
            for line in script_content.lines() {
                if line.contains("cargo") || line.contains("npm") || 
                   line.contains("pip install") {
                    
                    let manager = if line.contains("cargo") {
                        DependencySource::CargoToml
                    } else if line.contains("npm") {
                        DependencySource::NpmPkgJson
                    } else {
                        DependencySource::PipRequirements
                    };

                    let (name, version) = Self::extract_dependency_info(line);
                    
                    jobs.push(JobDefinition {
                        name: "before_script".to_string(),
                        platform: None,
                        steps: vec![StepDefinition {
                            run: Some(line.to_string()),
                            name: Some("install_dependencies".to_string()),
                            uses: None,
                            with: HashMap::new(),
                        }],
                        env_vars: HashMap::new(),
                    });

                    dependencies.push(DependencyDeclaration {
                        package_name: name,
                        version_constraint: version,
                        manager,
                        context: Some("before_script".to_string()),
                    });
                }
            }
        }

        Ok(PipelineConfig {
            name: format!("gitlab_{}", name),
            platform: PlatformType::GitLabCi,
            stages,
            jobs,
            dependencies: Vec::new(), // Will be populated above
            resolved_at: SystemTime::now(),
        })
    }

    /// Parse Cargo.toml for Rust dependencies
    fn parse_cargo_toml(&self, content: &str) -> Option<PipelineConfig> {
        let mut dependencies = Vec::new();
        
        // Extract [dependencies] section
        if let Some(start) = content.find("[dependencies]") {
            let end = content[start..].find(']').map(|i| start + i).unwrap_or(content.len());
            let deps_content = &content[start..end];

            for line in deps_content.lines() {
                // Parse "name = \"version\"" or "name = { version = \"ver\" }"
                if let Some(eq_pos) = line.find('=') {
                    let left = line[..eq_pos].trim();
                    let right = &line[eq_pos + 1..];

                    let (name, version) = if left.contains('"') || left.contains('\'') {
                        // Simple string format: "name" = "version"
                        let name_part = left.trim_matches(|c| c == '"' || c == '\'');
                        let ver_part = right.split('=').next().unwrap_or("").trim();
                        
                        (name_part.to_string(), 
                         if ver_part.starts_with('"') {
                             ver_part[1..ver_part.len()-1].to_string()
                         } else {
                             ver_part.to