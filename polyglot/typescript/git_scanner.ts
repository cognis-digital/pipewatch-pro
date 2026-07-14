import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface ScanResult {
  repository: string;
  timestamp: Date;
  findings: Finding[];
  metadata: Metadata;
}

interface Finding {
  id: string;
  severity: Severity;
  category: Category;
  message: string;
  location?: string;
  evidence?: string;
  remediation?: string;
}

type Severity = 'critical' | 'high' | 'medium' | 'low';
type Category = 
  | 'dependency' 
  | 'secret' 
  | 'config' 
  | 'commit' 
  | 'branch' 
  | 'ci-cd' 
  | 'other';

interface Metadata {
  branch: string;
  commitHash: string;
  author?: string;
  totalCommits: number;
}

// ============================================================================
// CONFIGURATION
// ============================================================================

const CONFIG = {
  defaultBranches: ['main', 'master', 'develop'],
  knownSecretPatterns: [
    /(?<type>[A-Z]+)_KEY\s*[:=]\s*["'](?<value>[\w\-]{16,})["']/gi,
    /(?<type>[A-Z]+)_SECRET\s*[:=]\s*["'](?<value>[\w\-]{16,})["']/gi,
    /(?<type>[A-Z]+)_TOKEN\s*[:=]\s*["'](?<value>[\w\-]{16,})["']/gi,
    /(?<type>[A-Z]+)_PASSWORD\s*[:=]\s*["'](?<value>[\w\-]{16,})["']/gi,
  ],
  knownVulnerablePackages: [
    { name: 'lodash', versions: ['<4.17.21'], cve: 'CVE-2021-23960' },
    { name: 'minimist', versions: ['<1.2.8'], cve: 'CVE-2021-23961' },
    { name: 'node-fetch', versions: ['<2.7.0'], cve: 'CVE-2021-23962' },
  ],
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function normalizePath(p: string): string {
  return path.normalize(p).replace(/\\/g, '/');
}

function getGitRoot(dir: string): string | null {
  try {
    const result = execSync(`git rev-parse --show-toplevel`, { 
      cwd: dir, 
      encoding: 'utf-8' 
    }).trim();
    return result;
  } catch (e) {
    return null;
  }
}

function getGitBranch(): string | null {
  try {
    return execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf-8' })
      .trim();
  } catch (e) {
    return 'unknown';
  }
}

function getCommitHash(): string | null {
  try {
    const hash = execSync('git rev-parse --short HEAD', { 
      cwd: process.cwd(), 
      encoding: 'utf-8' 
    }).trim();
    return hash;
  } catch (e) {
    return 'unknown';
  }
}

function getCommitAuthor(): string | null {
  try {
    const author = execSync('git log -1 --format="%an <%ae>"', { 
      cwd: process.cwd(), 
      encoding: 'utf-8' 
    }).trim();
    return author || 'unknown';
  } catch (e) {
    return null;
  }
}

function getCommitCount(): number | null {
  try {
    const count = execSync('git rev-list --count HEAD', { 
      cwd: process.cwd(), 
      encoding: 'utf-8' 
    }).trim();
    return parseInt(count, 10) || 0;
  } catch (e) {
    return null;
  }
}

// ============================================================================
// DEPENDENCY SCANNER
// ============================================================================

interface DependencyInfo {
  name: string;
  version: string;
  vulnerable?: boolean;
  cve?: string;
}

function parsePackageJson(): DependencyInfo[] | null {
  try {
    const content = fs.readFileSync('package.json', 'utf-8');
    const pkg = JSON.parse(content);
    
    if (!pkg.dependencies && !pkg.devDependencies) return [];
    
    const allDeps: Record<string, string> = {};
    [...(pkg.dependencies || {}), ...(pkg.devDependencies || {})]
      .forEach((dep: any) => {
        Object.assign(allDeps, dep);
      });
    
    return Object.entries(allDeps).map(([name, version]) => ({
      name,
      version,
    }));
  } catch (e) {
    return null;
  }
}

function parsePipfile(): DependencyInfo[] | null {
  try {
    const content = fs.readFileSync('Pipfile', 'utf-8');
    // Simple regex-based parsing for Pipenv
    const deps: Record<string, string> = {};
    
    // Match [[source]] sections and package definitions
    const packageRegex = /(\w+)[\s=]+["']([^"']+)["']/g;
    let match;
    
    while ((match = packageRegex.exec(content)) !== null) {
      deps[match[1]] = match[2];
    }
    
    return Object.entries(deps).map(([name, version]) => ({
      name,
      version,
    }));
  } catch (e) {
    return null;
  }
}

function parseRequirementsTxt(): DependencyInfo[] | null {
  try {
    const content = fs.readFileSync('requirements.txt', 'utf-8');
    
    // Parse simple requirements format
    const deps: Record<string, string> = {};
    const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));
    
    for (const line of lines) {
      const match = line.match(/^(\w+)[\s=]?(?:["'])([^"']+)["']?/);
      if (match) {
        deps[match[1]] = match[2];
      } else if (/^\S+/.test(line)) {
        // Handle pip-style: package==version
        const parts = line.split(/[=<>!~]/).filter(Boolean);
        if (parts.length >= 2) {
          deps[parts[0]] = parts.slice(1).join('');
        } else {
          deps[line.trim()] = 'latest';
        }
      }
    }
    
    return Object.entries(deps).map(([name, version]) => ({
      name,
      version,
    }));
  } catch (e) {
    return null;
  }
}

function checkVulnerabilities(deps: DependencyInfo[]): DependencyInfo[] {
  const vulnerableDeps = deps.filter(dep => {
    for (const vuln of CONFIG.knownVulnerablePackages) {
      if (dep.name.toLowerCase() === vuln.name.toLowerCase()) {
        // Simple version comparison (supports semver-like format)
        const [major, minor] = dep.version.split('.').map(Number);
        const [vMajor, vMinor] = vuln.versions[0].split('.').map(Number);
        
        if (major < vMajor || (major === vMajor && minor < vMinor)) {
          return true;
        }
      }
    }
    return false;
  });

  // Add CVE info to vulnerable deps
  for (const dep of vulnerableDeps) {
    for (const vuln of CONFIG.knownVulnerablePackages) {
      if (dep.name.toLowerCase() === vuln.name.toLowerCase()) {
        dep.vulnerable = true;
        dep.cve = vuln.cve;
        break;
      }
    }
  }

  return vulnerableDeps;
}

// ============================================================================
// SECRET DETECTOR
// ============================================================================

function detectSecrets(): Finding[] {
  const findings: Finding[] = [];
  
  // Check common config files for secrets
  const configFiles = [
    '.env', '.env.local', 'config.json', 'settings.yaml',
    'credentials.json', 'secrets.yml'
  ];

  for (const file of configFiles) {
    if (!fs.existsSync(file)) continue;
    
    try {
      const content = fs.readFileSync(file, 'utf-8');
      
      // Check against known patterns
      let foundSecret: Finding | null = null;
      
      for (const pattern of CONFIG.knownSecretPatterns) {
        const match = content.match(pattern);
        if (match && match.groups) {
          foundSecret = {
            id: `secret-${file}-${Date.now()}`,
            severity: 'critical',
            category: 'secret',
            message: `Potential hardcoded secret in ${file}:`,
            location: file,
            evidence: `${match[0].substring(0, 100)}...`,
            remediation: `Move to environment variables or use a secrets manager.`,
          };
          break;
        }
      }

      if (foundSecret) {
        findings.push(foundSecret);
      }
    } catch (e) {
      // Ignore read errors
    }
  }

  return findings;
}

// ============================================================================
// CI/CD CONFIGURATION ANALYZER
// ============================================================================

interface CICDConfig {
  platform: string | null;
  workflows: any[];
  pipelines: any[];
  jobs: number;
}

function analyzeCICDConfigs(): Finding[] {
  const findings: Finding[] = [];
  
  // Check for GitHub Actions workflow files
  if (fs.existsSync('.github/workflows')) {
    try {
      const workflowsPath = '.github/workflows';
      const files = fs.readdirSync(workflowsPath);
      
      let totalJobs = 0;
      let hasDeployJob = false;
      let hasTestJob = false;
      
      for (const file of files) {
        if (!file.endsWith('.yml') && !file.endsWith('.yaml')) continue;
        
        const content = fs.readFileSync(path.join(workflowsPath, file), 'utf-8');
        
        // Check for common patterns
        if (content.includes('deploy:') || content.includes('name: deploy')) {
          hasDeployJob = true;
        }
        if (content.includes('test:') || content.includes('name: test') || 
            content.includes('unit-test')) {
          hasTestJob = true;
        }
        
        // Look for secrets in workflow files
        const secretMatch = content.match(/secrets\./g);
        if (secretMatch && secretMatch.length > 2) {
          findings.push({
            id: `ci-cd-${file}-secrets`,
            severity: 'medium',
            category: 'ci-cd',
            message: `Multiple secrets references in ${file}`,
            location: `.github/workflows/${file}`,
            evidence: `${secretMatch.length} secret references found`,
            remediation: 'Review if all secrets are necessary and use least privilege.',
          });
        }
        
        totalJobs++;
      }
    } catch (e) {
      // Ignore errors
    }
  }

  return findings;
}

// ============================================================================
// COMMIT HISTORY ANALYZER
// ============================================================================

interface CommitAnalysis {
  totalCommits: number | null;
  recentActivity: string | null;
  suspiciousPatterns: Finding[];
}

function analyzeCommitHistory(): CommitAnalysis {
  const analysis: CommitAnalysis = {
    totalCommits: getCommitCount(),
    recentActivity: null,
    suspiciousPatterns: [],
  };

  try {
    // Get last 10 commits for activity check
    const lastCommits = execSync('git log -10 --format="%h %ad %s"', {
      cwd: process.cwd(),
      encoding: 'utf-8',
    }).trim();

    if (lastCommits) {
      analysis.recentActivity = lastCommits.substring(0, 200);
    }

    // Check for suspicious commit patterns
    const suspiciousPatterns: Finding[] = [];

    // Look for commits with many files changed at once
    try {
      const largeCommitCheck = execSync('git log -10 --name-only', {
        cwd: process.cwd(),
        encoding: 'utf-8',
      });

      const lines = largeCommitCheck.split('\n');
      let maxFilesInOneCommit = 0;
      
      for (const line of lines) {
        if (!line.trim()) continue;
        // Count files in current commit block
        // Simplified: just check if we're at a new commit
        const match = line.match(/^commit/);
        if (match) {
          maxFilesInOneCommit = 0;
        } else if (/^[a-f0-9]{7}/.test(line)) {
          maxFilesInOneCommit++;
        }
      }

      if (maxFilesInOneCommit > 50) {
        suspiciousPatterns.push({
          id: 'commit-large-changes',
          severity: 'low',
          category: 'commit',
          message: `Large commit detected with ${maxFilesInOneCommit} files changed`,
          remediation: 'Consider breaking large changes into smaller commits.',
        });
      }
    } catch (e) {
      // Ignore errors
    }

  } catch (e) {
    // Ignore errors in history analysis
  }

  return analysis;
}

// ============================================================================
// MAIN SCANNER CLASS
// ============================================================================

export class GitScanner {
  private currentDir: string = process.cwd();
  private results: ScanResult[] = [];

  constructor(private options: ScannerOptions = {}) {}

  /**
   * Main entry point for scanning a repository
   */
  async scan(): Promise<ScanResult> {
    const gitRoot = getGitRoot(this.currentDir);
    
    if (!gitRoot) {
      throw new Error('Not in a Git repository');
    }

    // Change to git root for consistent results
    this.currentDir = gitRoot;

    try {
      return await this.performFullScan();
    } finally {
      this.currentDir = process.cwd();
    }
  }

  private async performFullScan(): Promise<ScanResult> {
    const startTime = Date.now();
    
    // Gather metadata
    const metadata: Metadata = {
      branch: getGitBranch(),
      commitHash: getCommitHash(),
      author: getCommitAuthor(),
      totalCommits: getCommitCount() || 0,
    };

    // Run all scanners in parallel
    const [deps, secrets, cicd, commits] = await Promise.all([
      this.scanDependencies(),
      detectSecrets(),
      analyzeCICDConfigs(),
      analyzeCommitHistory(),
    ]);

    // Combine findings
    const allFindings: Finding[] = [];
    
    if (deps) {
      const vulnerable = checkVulnerabilities(deps);
      
      for (const dep of deps) {
        if (!dep.vulnerable && !CONFIG.knownVulnerablePackages.some(
          v => dep.name.toLowerCase() === v.name.toLowerCase())
        ) {
          continue; // Not a known vulnerability, skip detailed output
        }

        allFindings.push({
          id: `dependency-${dep.name}-${dep.version}`,
          severity: dep.vulnerable ? 'high' : 'low',
          category: 'dependency',
          message: `${dep.name}@${dep.version} ${dep.vulnerable ? '(potentially vulnerable)' : ''}`,
          location: 'package.json / requirements.txt / Pipfile',
          evidence: `Version: ${dep.version}`,
          remediation: dep.vulnerable && dep.cve 
            ? `Update to latest version. CVE: ${dep.cve}`
            : 'Review dependency for known issues.',
        });
      }

      if (vulnerable.length > 0) {
        allFindings.push({
          id: 'dependency-summary',
          severity: 'high',
          category: 'dependency',
          message: `${vulnerable.length} potentially vulnerable dependencies found`,
          evidence: `Check individual findings for details.`,
          remediation: 'Run update commands and verify CVE fixes.',
        });
      }
    }

    allFindings.push(...secrets);
    allFindings.push(...cicd);
    
    if (commits.suspiciousPatterns.length > 0) {
      allFindings.push(...commits.suspiciousPatterns);
    }

    // Sort by severity
    const severityOrder: Record