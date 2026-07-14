import os
import re
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any


@dataclass
class CommitInfo:
    hash: str = ""
    author_name: str = ""
    author_email: str = ""
    date: datetime = None
    message: str = ""
    files_changed: List[str] = field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0


@dataclass
class ScanResult:
    commits: List[CommitInfo] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class GitScanner:
    """
    CI/CD supply-chain auditor for git repositories.
    
    Analyzes commit history to identify patterns relevant to:
    - GitHub Actions / GitLab CI pipeline changes
    - OWASP CI/CD Top 10 security concerns
    - Recent large-scale modifications
    """

    # Common CI/CD keywords and patterns
    CI_CD_KEYWORDS = {
        'github_actions': [r'actions/', r'\.github/workflows', r'gh-actions'],
        'gitlab_ci': [r'\.gitlab-ci\.yml', r'ci/gitlab-ci\.yml', r'gitlab-pipeline'],
        'jenkins': [r'jenkinsfile', r'\.jenkins/', r'JENKINSFILE'],
        'circleci': [r'\.circleci/config\.yml', r'circleci-config'],
        'travis': [r'\.travis\.yml', r'travis-ci'],
    }

    # OWASP CI/CD Top 10 relevant patterns
    SECURITY_PATTERNS = {
        'hardcoded_secrets': [
            r'(password|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*["\']?[\w\-]+',
            r'PRIVATE_KEY\s*[=:]\s*["\']?-----BEGIN',
            r'DATABASE_URL\s*[=:]\s*["\']?[a-z]+://',
        ],
        'recent_pipeline_changes': [
            r'\.github/workflows/.*\.yml',
            r'\.gitlab-ci\.yml',
            r'ci/ci\.yml',
        ],
    }

    def __init__(self, repo_path: str = ".", verbose: bool = False):
        self.repo_path = os.path.abspath(repo_path) if not os.path.isabs(repo_path) else repo_path
        self.verbose = verbose
        self._cache: Dict[str, Any] = {}

    @property
    def is_git_repo(self) -> bool:
        """Check if the path is a valid git repository."""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--is-inside-work-tree'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip() == 'true'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _run_git(self, args: List[str], cwd: str = None) -> subprocess.CompletedProcess:
        """Execute git command and return the result."""
        cmd = ['git'] + args
        if cwd is not None:
            cmd.extend(['-C', cwd])
        
        try:
            proc = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )
            return proc
        except subprocess.TimeoutExpired as e:
            if self.verbose:
                print(f"Git command timed out: {' '.join(cmd)}")
            raise

    def _parse_commit_message(self, message: str) -> Dict[str, Any]:
        """Extract structured data from commit message."""
        result = {
            'raw': message,
            'type': '',
            'scope': '',
            'subject': '',
            'body': '',
            'references': [],
        }

        # Parse conventional commits: type(scope): subject
        match = re.match(r'^(\w+)(?:\(([^)]+)\))?:\s*(.+)', message)
        if match:
            result['type'] = match.group(1).lower()
            result['scope'] = match.group(2) or ''
            result['subject'] = match.group(3).strip()

            # Extract references (issues, PRs, etc.)
            refs_match = re.findall(r'(?:#|PR|#)(\d+)', message)
            result['references'] = list(set(refs_match))

        return result

    def _get_commit_files(self, commit_hash: str) -> List[Dict[str, Any]]:
        """Get files changed in a specific commit."""
        try:
            proc = self._run_git(['diff-tree', '--no-commit-id', '--name-only', '-r', commit_hash])
            if proc.returncode == 0 and proc.stdout.strip():
                return [f.decode('utf-8').strip() for f in proc.stdout.splitlines()]
        except Exception:
            pass
        return []

    def _get_commit_stats(self, commit_hash: str) -> Dict[str, int]:
        """Get lines added/removed in a specific commit."""
        try:
            proc = self._run_git(['diff', '--stat', '--numstat', commit_hash])
            if proc.returncode == 0 and proc.stdout.strip():
                stats = {'added': 0, 'removed': 0}
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            stats['added'] += int(parts[1])
                            stats['removed'] += int(parts[2])
                        except ValueError:
                            continue
                return stats
        except Exception:
            pass
        return {'added': 0, 'removed': 0}

    def _get_commit_info(self, commit_hash: str) -> CommitInfo:
        """Get detailed information about a specific commit."""
        try:
            # Get author and date
            proc = self._run_git(['log', '-1', '--format=%an|%ae|%aI|%s|%b', commit_hash])
            
            if proc.returncode == 0 and proc.stdout.strip():
                parts = proc.stdout.split('|')
                
                info = CommitInfo(
                    hash=commit_hash,
                    author_name=parts[0] if len(parts) > 0 else '',
                    author_email=parts[1] if len(parts) > 1 else '',
                    date=datetime.fromisoformat(parts[2]) if len(parts) > 2 and parts[2].strip() else None,
                    message=parts[3] if len(parts) > 3 else '',
                )

                # Parse the commit message properly
                info.message = self._parse_commit_message(info.message)

                return info
        except Exception:
            pass
        
        return CommitInfo(hash=commit_hash)

    def _find_ci_cd_files(self, base_path: str = ".") -> List[str]:
        """Find all CI/CD configuration files in the repository."""
        ci_files = []
        
        # Common locations for CI/CD configs
        patterns = [
            '.github/workflows/*.yml',
            '.gitlab-ci.yml',
            'ci/ci.yml',
            'Jenkinsfile*',
            '.circleci/config.yml',
            '.travis.yml',
            'azure-pipelines.yml',
            'bitbucket-pipelines.yml',
        ]

        for pattern in patterns:
            try:
                proc = self._run_git(['ls-tree', '-r', '--name-only', 'HEAD'])
                if proc.returncode == 0 and proc.stdout.strip():
                    files = [f.decode('utf-8').strip() for f in proc.stdout.splitlines()]
                    
                    # Check against patterns
                    for file_path in files:
                        for pattern_str in patterns:
                            if re.search(pattern_str.replace('*', '.*'), file_path):
                                if file_path not in ci_files:
                                    ci_files.append(file_path)
            except Exception:
                continue
        
        return list(set(ci_files))

    def _check_for_secrets(self, content: str, filename: str = "") -> List[Dict[str, Any]]:
        """Check content for potential hardcoded secrets."""
        findings = []

        # Patterns to check
        secret_patterns = [
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?(\w+)', 'Potential password'),
            (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?(\S+)', 'API Key'),
            (r'(?i)(secret|token)\s*[=:]\s*["\']?(\S+)', 'Secret/Token'),
            (r'(?i)(private[_-]?key|priv[_-]key)\s*[=:]\s*["\']?(-----BEGIN[^-]+-----)', 'Private Key'),
        ]

        for pattern, description in secret_patterns:
            matches = re.findall(pattern, content)
            if matches:
                findings.append({
                    'type': description,
                    'pattern': pattern,
                    'matches': len(matches),
                    'filename': filename or 'unknown',
                    'severity': 'medium'
                })

        return findings

    def _analyze_commit_patterns(self, commits: List[CommitInfo]) -> Dict[str, Any]:
        """Analyze commit patterns for anomalies."""
        analysis = {
            'total_commits': len(commits),
            'commits_per_day': 0.0,
            'avg_files_per_commit': 0.0,
            'recent_spike': False,
            'large_changes': [],
            'pipeline_changes': [],
        }

        if not commits:
            return analysis

        # Calculate commits per day (last 30 days)
        now = datetime.now()
        thirty_days_ago = now - timedelta(days=30)
        
        recent_commits = [c for c in commits 
                        if c.date and thirty_days_ago <= c.date < now]
        
        if recent_commits:
            date_range = (now - min(c.date for c in recent_commits)).days or 1
            analysis['commits_per_day'] = len(recent_commits) / max(date_range, 1)

        # Check for recent spikes (>5 commits/day in last 24h)
        yesterday = now - timedelta(days=1)
        yesterday_commits = [c for c in commits if c.date and yesterday <= c.date < now]
        
        if yesterday_commits:
            avg_daily = len(yesterday_commits) / max(1, (now - min(c.date for c in yesterday_commits)).days or 1)
            analysis['recent_spike'] = avg_daily > 5

        # Calculate average files per commit
        total_files = sum(len(c.files_changed) for c in commits if c.files_changed)
        analysis['avg_files_per_commit'] = total_files / max(1, len(commits))

        # Find large changes (>1000 lines added/removed)
        for commit in commits:
            stats = self._get_commit_stats(commit.hash)
            if stats['added'] > 1000 or stats['removed'] > 1000:
                analysis['large_changes'].append({
                    'commit': commit.hash[:7],
                    'added': stats['added'],
                    'removed': stats['removed'],
                })

        # Find pipeline-related changes
        ci_files = self._find_ci_cd_files()
        for commit in commits:
            if any(cf in commit.files_changed for cf in ci_files):
                analysis['pipeline_changes'].append({
                    'commit': commit.hash[:7],
                    'files': [f for f in commit.files_changed if f in ci_files],
                    'date': commit.date.isoformat() if commit.date else '',
                })

        return analysis

    def _find_recent_pipeline_commits(self, days: int = 30) -> List[CommitInfo]:
        """Find commits that modified CI/CD pipeline files."""
        ci_files = self._find_ci_cd_files()
        
        if not ci_files:
            return []

        # Get recent commits and filter for pipeline changes
        proc = self._run_git(['log', f'--since={days} days ago', '--oneline'])
        
        if proc.returncode == 0 and proc.stdout.strip():
            lines = proc.stdout.splitlines()
            relevant_commits = []

            for line in reversed(lines):  # Most recent first
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    continue
                
                commit_hash, message = parts[0], ' '.join(parts[1:])

                # Check if this commit touched pipeline files
                for ci_file in ci_files:
                    if any(ci_file in f for f in self._get_commit_files(commit_hash)):
                        info = self._get_commit_info(commit_hash)
                        relevant_commits.append(info)
                        break

            return relevant_commits[:10]  # Limit to top 10 most recent
        return []

    def _generate_report(self, result: ScanResult) -> str:
        """Generate a human-readable report."""
        lines = [
            "=" * 60,
            "GIT SCANNER REPORT",
            f"Repository: {self.repo_path}",
            f"Scanned at: {datetime.now().isoformat()}",
            "=" * 60,
            "",
            "SUMMARY",
            "-" * 40,
        ]

        if result.stats.get('total_commits'):
            lines.append(f"Total commits analyzed: {result.stats['total_commits']}")
        
        if result.stats.get('commits_per_day', 0) > 3:
            lines.append(f"⚠️  High commit rate: {result.stats['commits_per_day']:.1f} commits/day")

        if result.findings:
            lines.extend([
                "",
                "FINDINGS",
                "-" * 40,
            ])

            for finding in result.findings[:20]:  # Limit to first 20
                severity_icon = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}.get(finding.get('severity', ''), '')
                lines.append(f"{severity_icon} [{finding.get('type', 'Unknown')}]")
                if finding.get('filename'):
                    lines.append(f"   File: {finding['filename']}")
                else:
                    lines.append(f"   Context: {finding.get('context', 'N/A')}")

        lines.extend([
            "",
            "PIPELINE ANALYSIS",
            "-" * 40,
        ])

        pipeline_changes = result.stats.get('pipeline_changes', [])
        if pipeline_changes:
            for change in pipeline_changes[:5]:
                lines.append(f"   • {change['commit']}: Modified {len(change['files'])} pipeline file(s)")
        else:
            lines.append("   No recent pipeline changes detected.")

        lines.extend([
            "",
            "=" * 60,
            "END OF REPORT",
            "=" * 60,
        ])

        return '\n'.join(lines)

    def scan(self, days: int = 30, detailed: bool = True) -> ScanResult:
        """
        Perform a comprehensive git repository scan.
        
        Args:
            days: Number of days to look back for commits (default: 30)
            detailed: Whether to include detailed analysis (default: True)
        
        Returns:
            A ScanResult object containing all findings and statistics.
        """
        result = ScanResult()

        if not self.is_git_repo:
            error_msg = f"Not a git repository: {self.repo_path}"
            result.findings.append({'type': 'error', 'message': error_msg, 'severity': 'high'})
            return result

        # Get recent commits
        proc = self._run_git(['log', f'--since={days} days ago', '--format=%H|%an|%ae|%aI|%s'])
        
        if proc.returncode == 0 and proc.stdout.strip():
            commit_hashes = []
            for line in proc.stdout.splitlines():
                parts = line.split('|')
                if len(parts) >= 1:
                    commit_hashes.append(parts[0])

            # Parse each commit
            result.commits = [self._get_commit_info(h) for h in commit_hashes]
        else:
            result.findings.append({
                'type': 'warning', 
                'message': 'Could not retrieve commit history',
                'severity': 'low'
            })

        # Analyze patterns
        if detailed:
            result.stats = self._analyze_commit_patterns(result.commits)
        
        # Find recent pipeline commits
        pipeline_commits = self._find_recent_pipeline_commits(days=days)
        result.stats['pipeline_changes'] = pipeline_commits
        
        # Check for potential secrets in recent files
        ci_files = self._find_ci_cd_files()
        if ci_files:
            for