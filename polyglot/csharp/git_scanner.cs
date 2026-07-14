using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using LibGit2Sharp;

namespace pipewatch_pro
{
    /// <summary>
    /// CI/CD Supply-Chain Auditor - Git Scanner Component
    /// </summary>
    public static class GitScanner
    {
        private const int MaxCommitsToAnalyze = 1000;
        private const string SuspiciousAuthorThreshold = "unknown";

        public record ScanResult(
            string RepositoryPath,
            List<CommitAnalysis> CommitAnalyses,
            Dictionary<string, int> AuthorStats,
            FileInfoSummary FileChanges,
            string? SecurityFindings,
            bool IsClean);

        public record CommitAnalysis(
            ObjectId Sha,
            string Message,
            DateTime Date,
            string AuthorName,
            int FilesChanged,
            int LinesAdded,
            int LinesDeleted,
            List<string> ModifiedFiles);

        public record FileInfoSummary(
            int TotalCommits,
            int UniqueAuthors,
            DateTime FirstCommitDate,
            DateTime LastCommitDate,
            string? MostActiveAuthor);

        /// <summary>
        /// Main entry point for scanning a git repository.
        /// </summary>
        public static async Task<ScanResult> ScanAsync(string repoPath)
        {
            var result = await ScanCore(repoPath);
            return result;
        }

        private static ScanResult ScanCore(string repoPath)
        {
            if (!Directory.Exists(repoPath))
                throw new DirectoryNotFoundException($"Repository not found: {repoPath}");

            var repo = OpenRepo(repoPath);
            var head = repo.Head.Tip;

            // Limit commits for performance on large repos
            var commitsToAnalyze = Math.Min(
                MaxCommitsToAnalyze, 
                repo.Commits.Count()
            );

            var commitAnalyses = new List<CommitAnalysis>();
            var authorStats = new Dictionary<string, int>();
            var fileChanges = new FileInfoSummary(0, 0, DateTime.MinValue, DateTime.MaxValue, null);

            // Analyze commits in reverse chronological order (newest first)
            foreach (var commit in repo.Commits.QueryBy().Take(commitsToAnalyze))
            {
                var analysis = AnalyzeCommit(commit);
                commitAnalyses.Add(analysis);

                // Track author stats
                if (!authorStats.ContainsKey(analysis.AuthorName))
                    authorStats[analysis.AuthorName] = 0;
                authorStats[analysis.AuthorName]++;

                // Update file change summary
                if (analysis.Date < fileChanges.FirstCommitDate)
                    fileChanges.FirstCommitDate = analysis.Date;
                if (analysis.Date > fileChanges.LastCommitDate)
                    fileChanges.LastCommitDate = analysis.Date;
            }

            // Find most active author
            var mostActiveAuthor = authorStats.OrderByDescending(kvp => kvp.Value).First().Key;
            fileChanges.MostActiveAuthor = mostActiveAuthor;

            // Check for security findings
            var securityFindings = DetectSecurityIssues(repo, commitAnalyses);

            // Determine if repository is "clean" (no major red flags)
            var isClean = !securityFindings.Any() && 
                         authorStats.Count < 50 && // Too many authors might indicate chaos
                         fileChanges.TotalCommits > 10; // Must have some history

            return new ScanResult(
                repoPath,
                commitAnalyses,
                authorStats,
                fileChanges,
                securityFindings,
                isClean
            );
        }

        private static CommitAnalysis AnalyzeCommit(Commit commit)
        {
            var files = commit.Files;
            
            int totalFilesChanged = 0;
            int linesAdded = 0;
            int linesDeleted = 0;
            var modifiedFiles = new List<string>();

            foreach (var file in files)
            {
                if (!file.IsNew && !file.IsDeleted)
                {
                    totalFilesChanged++;
                    modifiedFiles.Add(file.FilePath);
                    
                    // Track line changes
                    linesAdded += file.Additions;
                    linesDeleted += file.Deletions;
                }
            }

            return new CommitAnalysis(
                commit.Id,
                TruncateMessage(commit.Message),
                commit.CommittedDate,
                GetAuthorName(commit.Author.Name),
                totalFilesChanged,
                linesAdded,
                linesDeleted,
                modifiedFiles
            );
        }

        private static string GetAuthorName(string name)
        {
            // Normalize author names for comparison
            return name?.Trim() ?? "Unknown";
        }

        private static string TruncateMessage(string message, int maxLength = 100)
        {
            if (string.IsNullOrEmpty(message))
                return "(empty)";

            if (message.Length <= maxLength)
                return message;

            var truncated = message.Substring(0, maxLength);
            
            // Try to find a clean break point
            var lastSpace = truncated.LastIndexOf(' ', maxLength - 1);
            if (lastSpace > 0)
                truncated = truncated.Substring(0, lastSpace + 1);

            return truncated + "...";
        }

        private static List<string> DetectSecurityIssues(Repository repo, List<CommitAnalysis> commits)
        {
            var findings = new List<string>();

            // Check for suspicious commit patterns
            foreach (var commit in commits)
            {
                // Large single-file changes might indicate mass modifications
                if (commit.FilesChanged > 50 && commit.ModifiedFiles.Count < 10)
                {
                    findings.Add($"Large modification: {commit.FilesChanged} files changed in one commit");
                }

                // Check for potential "god commits" - massive line changes
                int netChange = Math.Abs(commit.LinesAdded - commit.LinesDeleted);
                if (netChange > 1000)
                {
                    findings.Add($"Massive change: ±{netChange} lines in one commit");
                }

                // Check for suspicious author names
                var normalizedName = GetAuthorName(commit.AuthorName).ToLowerInvariant();
                if (normalizedName.Contains("unknown") || 
                    normalizedName.Contains("admin") ||
                    normalizedName.Contains("root"))
                {
                    findings.Add($"Suspicious author: '{commit.AuthorName}'");
                }
            }

            // Check for OWASP CI/CD Top 10 patterns in commit messages
            var owaspPatterns = new[]
            {
                "api_key", "secret", "token", "password", 
                ".env", "config.json", "credentials"
            };

            foreach (var commit in commits)
            {
                foreach (var pattern in owaspPatterns)
                {
                    if (commit.Message.ToLowerInvariant().Contains(pattern))
                    {
                        findings.Add($"Potential credential exposure: '{pattern}' found in message");
                    }
                }
            }

            // Check for recent rapid commits (potential bot activity or rushed merge)
            var commitDates = commits.Select(c => c.Date).OrderByDescending(d => d);
            
            if (commitDates.Count >= 3)
            {
                var timeSpan = commitDates.First() - commitDates.Last();
                int totalMinutes = (int)(timeSpan.TotalMinutes);
                
                // If 10+ commits in less than 5 minutes, flag it
                if (totalMinutes > 0 && 
                    commits.Count >= 3 && 
                    (commits[0].Date - commits[commits.Count - 1].Date).TotalMinutes < totalMinutes)
                {
                    var avgRate = totalMinutes / Math.Max(1, commits.Count);
                    if (avgRate < 5) // Less than 5 minutes per commit average
                    {
                        findings.Add($"Rapid commit activity: ~{avgRate:F2} min/commit");
                    }
                }
            }

            return findings;
        }

        private static Repository OpenRepo(string path)
        {
            var repo = new Repository(path);
            
            // Verify it's actually a git repository
            if (repo.IsBare || !repo.Head.Tip.IsValid)
            {
                throw new InvalidDataException(
                    $"Repository at '{path}' is bare or has no commits"
                );
            }

            return repo;
        }

        /// <summary>
        /// Quick health check - returns a simple status without full analysis.
        /// </summary>
        public static async Task<HealthCheckResult> HealthCheckAsync(string path)
        {
            try
            {
                var repo = OpenRepo(path);
                
                // Basic stats
                var head = repo.Head.Tip;
                var totalCommits = repo.Commits.Count();
                
                // Get unique authors from recent history
                var recentCommits = repo.Commits.QueryBy().Take(100).ToList();
                var uniqueAuthors = new HashSet<string>();
                foreach (var commit in recentCommits)
                    uniqueAuthors.Add(commit.Author.Name);

                return new HealthCheckResult(
                    status: "healthy",
                    totalCommits,
                    uniqueAuthors.Count,
                    head.CommittedDate.ToString("yyyy-MM-dd"),
                    null
                );
            }
            catch (Exception ex)
            {
                return new HealthCheckResult(
                    status: "unhealthy",
                    0,
                    0,
                    DateTime.UtcNow.ToString(),
                    ex.Message
                );
            }
        }

        /// <summary>
        /// Result for quick health checks.
        /// </summary>
        public record HealthCheckResult(
            string Status,
            int TotalCommits,
            int UniqueAuthors,
            string LastCommitDate,
            string? Error);

        // ============================================
        // RUNNABLE DEMO / ENTRY POINT
        // ============================================
        public static void Main(string[] args)
        {
            Console.WriteLine("=== Pipewatch-Pro Git Scanner ===\n");

            var repoPath = args.Length > 0 ? args[0] : ".";
            
            try
            {
                Console.WriteLine($"Scanning: {repoPath}");
                
                // Run the full scan
                var result = ScanCore(repoPath);
                
                // Print summary
                PrintSummary(result);
                
                // Print detailed findings if any
                if (!result.SecurityFindings.IsNullOrEmpty())
                {
                    Console.WriteLine("\n--- Security Findings ---");
                    foreach (var finding in result.SecurityFindings)
                        Console.WriteLine($"  ⚠️  {finding}");
                }

                // Print author statistics
                Console.WriteLine($"\n--- Author Statistics ---");
                var sortedAuthors = result.AuthorStats
                    .OrderByDescending(kvp => kvp.Value)
                    .Take(10);
                
                foreach (var (author, count) in sortedAuthors)
                {
                    var percentage = 100.0 * count / Math.Max(1, result.FileInfoSummary.TotalCommits);
                    Console.WriteLine($"  {author,-35} : {count:D4} commits ({percentage:F2}%)");
                }

                // Print file change summary
                Console.WriteLine($"\n--- Repository Summary ---");
                Console.WriteLine($"  Total Commits:    {result.FileInfoSummary.TotalCommits:N0}");
                Console.WriteLine($"  Unique Authors:   {result.FileInfoSummary.UniqueAuthors}");
                Console.WriteLine($"  Date Range:       {result.FileInfoSummary.FirstCommitDate:yyyy-MM-dd} to " +
                             $"{result.FileInfoSummary.LastCommitDate:yyyy-MM-dd}");
                Console.WriteLine($"  Most Active:      {result.FileInfoSummary.MostActiveAuthor ?? "Unknown"}");

                // Final status
                var status = result.IsClean ? "CLEAN" : "REQUIRES REVIEW";
                var emoji = result.IsClean ? "✅" : "⚠️";
                
                Console.WriteLine($"\n{emoji} Status: {status}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                if (ex.InnerException != null)
                    Console.WriteLine($"  Inner: {ex.InnerException.Message}");
                
                Environment.Exit(1);
            }

            // Keep console open on Windows for easier inspection
#if !NETSTANDARD2_0
            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
#endif
        }

        private static void PrintSummary(ScanResult result)
        {
            var summary = new StringBuilder();
            
            // Create a quick overview
            summary.AppendLine($"Repository: {result.RepositoryPath}");
            summary.AppendLine($"Total Commits Analyzed: {result.FileInfoSummary.TotalCommits:N0}");
            summary.AppendLine($"Unique Authors: {result.FileInfoSummary.UniqueAuthors}");
            summary.AppendLine($"Date Range: {result.FileInfoSummary.FirstCommitDate:yyyy-MM-dd HH:mm} to " +
                         $"{result.FileInfoSummary.LastCommitDate:yyyy-MM-dd HH:mm}");

            // Calculate commit velocity
            if (result.FileInfoSummary.TotalCommits > 1)
            {
                var timeSpan = result.FileInfoSummary.LastCommitDate - 
                              result.FileInfoSummary.FirstCommitDate;
                double days = Math.Max(0.001, timeSpan.TotalDays);
                double commitsPerDay = result.FileInfoSummary.TotalCommits / days;
                
                summary.AppendLine($"Velocity: {commitsPerDay:F2} commits/day");
            }

            // Check for anomalies
            var anomalies = new List<string>();

            if (result.FileInfoSummary.UniqueAuthors > 50)
                anomalies.Add("High author count (>50 unique authors)");

            if (result.FileInfoSummary.TotalCommits < 10 && 
                result.FileInfoSummary.LastCommitDate - result.FileInfoSummary.FirstCommitDate < TimeSpan.FromDays(365))
            {
                anomalies.Add("Very recent repository (<10 commits in last year)");
            }

            if (result.SecurityFindings != null && result.SecurityFindings.Count > 0)
            {
                anomalies.Add($"Security findings: {result.SecurityFindings.Count} issues detected");
            }

            if (!anomalies.Any())
                summary.AppendLine("No significant anomalies detected.");
            else
            {
                summary.AppendLine("\nAnomalies Detected:");
                foreach (var anomaly in anomalies)
                    summary.AppendLine($"  • {anomaly}");
            }

            Console.WriteLine(summary.ToString());
        }
    }

    // ============================================
    // EXTENSION METHODS FOR GITHUB/GITLAB INTEGRATION
    // ============================================
    public static class RepositoryExtensions
    {
        /// <summary>
        /// Checks if a repository is likely from GitHub (has .github folder or workflow files).
        /// </summary>
        public static bool IsLikelyGitHubRepo(this Repository repo)
        {
            var githubIndicators = new[]
            {
                ".github", "workflows", ".gitignore", 
                "README.md", "LICENSE"
            };

            foreach (var indicator in githubIndicators)
            {
                try
                {
                    if (repo.Files.Contains(indicator))
                        return true;
                    
                    // Check for workflow files specifically
                    var workflowsPath = Path.Combine(repo.Path, ".github", "workflows");
                    if (Directory.Exists(workflowsPath))
                        return true;
                }
                catch
                {
                    // Ignore IO errors
                }
            }

            return false;
        }

        /// <summary>
        /// Checks for GitLab CI configuration.
        /// </summary>
        public static bool IsLikelyGitLabRepo(this Repository repo)
        {
            var gitlabIndicators = new[]
            {
                ".gitlab-ci.yml", ".gitlab-ci.yaml", 
                "ci/", ".gitlab"
            };

            foreach (var indicator in gitlabIndicators)
            {
                try
                {
                    if (repo.Files.Contains(indicator))
                        return true;
                }
                catch
                {
                    // Ignore IO errors
                }
            }

            return false;
        }

        /// <summary>
        /// Checks for OWASP CI/CD Top 10 related files.
        /// </summary>
        public static bool HasOWASPChecks(this Repository repo)
        {
            var owaspIndicators = new[]
            {
                ".github/workflows/security.yml",
                ".gitlab-ci.yml", // GitLab CI often has security checks
                "sonar-project.properties",
                ".sonarqube"
            };

            foreach (var indicator in owaspIndicators)
            {
                try
                {
                    if (repo.Files.Contains(indicator))
                        return true;
                }
                catch
                {
                    // Ignore IO errors
                }
            }

            return false;
        }
    }
}