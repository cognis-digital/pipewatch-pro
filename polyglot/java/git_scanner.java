package polyglot.java;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.lib.RepositoryBuilder;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.transport.CredentialsProvider;
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Pipewatch-Pro: CI/CD Supply-Chain Auditor - Git Scanner Module
 * 
 * Scans Git repositories for OWASP CI/CD Top 10 vulnerabilities including:
 * - Hardcoded credentials in commit history
 * - Exposed API keys and tokens
 * - Private cryptographic material leaks
 */
public class GitScanner {

    // OWASP CI/CD Top 10 Pattern Categories
    private static final Map<String, List<Pattern>> SECRET_PATTERNS = new LinkedHashMap<>();

    static {
        // AWS Credentials
        addPattern("AWS Access Key", 
            "AKIA[0-9A-Z]{16}",
            "aws_secret_access_key",
            "AWS_SECRET_ACCESS_KEY");
        
        // Google Cloud
        addPattern("Google Service Account",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "gcp_service_account.json");
            
        // GitHub Personal Access Tokens
        addPattern("GitHub PAT",
            "ghp_[0-9a-zA-Z]{36}",
            "https://(github\\.com|api\\.github\\.com)/[^/]+/token/[0-9a-zA-Z]{36}");

        // Generic API Keys
        addPattern("Generic API Key",
            "\"api_key\"\\s*:\\s*\"[^\"]+\"",
            "API_KEY=",
            "apikey=\"");

        // Private Keys (RSA, ECDSA)
        addPattern("Private RSA/ECDSA Key",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----");

        // Database Connection Strings
        addPattern("Database Credentials",
            "(mysql|postgres|mongodb)://[^:]+:[^@]+@",
            "\"password\"\\s*:\\s*\"[^\"]+\"",
            "DB_PASSWORD=");

        // Slack/Slackbot Tokens
        addPattern("Slack Token",
            "xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
            "SLACK_TOKEN=");

        // Stripe Keys
        addPattern("Stripe Secret Key",
            "sk_live_[0-9a-zA-Z]{24}");

        // Generic Bearer Tokens
        addPattern("Bearer Token",
            "Bearer [0-9a-zA-Z_-]{36,}",
            "\"Authorization\":\\s*\"Bearer\\s+[^\"]+\"");

        // JWT Secrets
        addPattern("JWT Secret",
            "\"secret\"\\s*:\\s*\"[A-Za-z0-9+/=]+\"",
            "jwt_secret=");
    }

    private static void addPattern(String name, String... patterns) {
        SECRET_PATTERNS.computeIfAbsent(name.toLowerCase(), k -> new ArrayList<>());
        for (String p : patterns) {
            SECRET_PATTERNS.get(name.toLowerCase()).add(Pattern.compile(p, Pattern.CASE_INSENSITIVE));
        }
    }

    public static class ScanResult {
        private final String repositoryPath;
        private final int totalCommitsScanned;
        private final List<SecretFinding> findings;
        private final long scanDurationMs;

        public ScanResult(String repo, int commits, List<SecretFinding> findings, long duration) {
            this.repositoryPath = repo;
            this.totalCommitsScanned = commits;
            this.findings = findings;
            this.scanDurationMs = duration;
        }

        public String getRepositoryPath() { return repositoryPath; }
        public int getTotalCommitsScanned() { return totalCommitsScanned; }
        public List<SecretFinding> getFindings() { return findings; }
        public long getScanDurationMs() { return scanDurationMs; }

        @Override
        public String toString() {
            return "ScanResult{" +
                    "repository='" + repositoryPath + '\'' +
                    ", commits=" + totalCommitsScanned +
                    ", findings=" + findings.size() +
                    ", duration=" + scanDurationMs + "ms" + '}';
        }
    }

    public static class SecretFinding {
        private final String category;
        private final String patternName;
        private final String matchSnippet;
        private final int commitHash;
        private final String commitDate;
        private final String author;

        public SecretFinding(String cat, String name, String snippet, 
                           int hash, String date, String author) {
            this.category = cat;
            this.patternName = name;
            this.matchSnippet = snippet;
            this.commitHash = hash;
            this.commitDate = date;
            this.author = author;
        }

        @Override
        public String toString() {
            return "SecretFinding{" +
                    "category='" + category + '\'' +
                    ", pattern='" + patternName + '\'' +
                    ", snippet='" + matchSnippet.substring(0, Math.min(matchSnippet.length(), 50)) + "..." +
                    ", commit=" + commitHash +
                    ", date=" + commitDate +
                    ", author=" + author + '}';
        }
    }

    public static ScanResult scan(Path repoPath) {
        long start = System.currentTimeMillis();
        List<SecretFinding> findings = new ArrayList<>();

        try (Git git = Git.open(repoPath.toFile())) {
            Repository repository = git.getRepository();
            
            // Get all commits for historical scanning
            Iterable<RevCommit> commits = git.log().call();
            int totalCommits = 0;
            
            for (RevCommit commit : commits) {
                totalCommits++;
                
                // Scan commit message and author info
                scanCommitMetadata(commit, findings);
                
                // Get file content at this commit for pattern matching
                try (var reader = Files.newBufferedReader(
                        repository.open(commit.getTree().getPath(), 
                            org.eclipse.jgit.lib.FileMode.TEXT))) {
                    String content = reader.lines()
                        .collect(Collectors.joining("\n"));
                    
                    // Scan file content against patterns
                    scanContent(content, commit, findings);
                } catch (Exception e) {
                    // Binary files or read errors - skip silently
                }

                // Check if this is a config file that might contain secrets
                if (commit.getTree().getPath().toString()
                        .toLowerCase().contains(".git/config")) {
                    scanGitConfig(commit, findings);
                }
            }

        } catch (Exception e) {
            System.err.println("Error scanning repository: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - start;
        return new ScanResult(repoPath.toString(), totalCommits, findings, duration);
    }

    private static void scanCommitMetadata(RevCommit commit, List<SecretFinding> findings) {
        // Check commit message for obvious secrets
        String msg = commit.getFullMessage();
        
        // Look for URL patterns that might expose tokens
        Pattern urlPattern = Pattern.compile("https?://[^\\s\"']+");
        Matcher matcher = urlPattern.matcher(msg);
        
        while (matcher.find()) {
            String url = matcher.group();
            
            // Check if URL contains potential token parameters
            for (String param : Arrays.asList("token", "auth", "api_key", "secret")) {
                Pattern paramPattern = Pattern.compile(param + "[=\\?][^\s\"']+");
                Matcher pMatcher = paramPattern.matcher(url);
                
                while (pMatcher.find()) {
                    String potentialSecret = pMatcher.group();
                    
                    // Check against our patterns
                    for (Map.Entry<String, List<Pattern>> entry : SECRET_PATTERNS.entrySet()) {
                        for (Pattern p : entry.getValue()) {
                            if (p.matcher(potentialSecret).find()) {
                                findings.add(new SecretFinding(
                                    "URL Parameter", 
                                    entry.getKey(), 
                                    potentialSecret,
                                    commit.getCommit().getName(),
                                    formatDate(commit.getCommit().getCommitterIdent()),
                                    commit.getAuthorIdent().getName()));
                            }
                        }
                    }
                }
            }
        }
    }

    private static void scanContent(String content, RevCommit commit, List<SecretFinding> findings) {
        // Check against all secret patterns
        for (Map.Entry<String, List<Pattern>> entry : SECRET_PATTERNS.entrySet()) {
            String category = entry.getKey();
            
            for (Pattern p : entry.getValue()) {
                Matcher m = p.matcher(content);
                
                while (m.find()) {
                    findings.add(new SecretFinding(
                        category,
                        entry.getKey(),
                        m.group() + " at offset " + m.start(),
                        commit.getCommit().getName(),
                        formatDate(commit.getCommit().getCommitterIdent()),
                        commit.getAuthorIdent().getName()));
                }
            }
        }
    }

    private static void scanGitConfig(RevCommit commit, List<SecretFinding> findings) {
        // .git/config often contains remote credentials or auth tokens
        String configContent = readTextFile(commit.getTree(), ".git/config");
        
        if (configContent != null && !configContent.isEmpty()) {
            // Check for common credential patterns in git config
            Pattern sshPattern = Pattern.compile("ssh.*password|Password\\s*:\\s*\"[^\"]+\"");
            Matcher m = sshPattern.matcher(configContent);
            
            while (m.find()) {
                findings.add(new SecretFinding(
                    "Git Config",
                    "SSH Password in .git/config",
                    m.group(),
                    commit.getCommit().getName(),
                    formatDate(commit.getCommit().getCommitterIdent()),
                    commit.getAuthorIdent().getName()));
            }

            // Check for credential helper that might expose secrets
            Pattern credHelperPattern = Pattern.compile("credential.*helper\\s*=\\s*\"[^\"]+\"");
            m = credHelperPattern.matcher(configContent);
            
            while (m.find()) {
                findings.add(new SecretFinding(
                    "Git Config",
                    "Credential Helper in .git/config",
                    m.group(),
                    commit.getCommit().getName(),
                    formatDate(commit.getCommit().getCommitterIdent()),
                    commit.getAuthorIdent().getName()));
            }
        }
    }

    private static String readTextFile(org.eclipse.jgit.lib.TreeEntry tree, String path) {
        try (var reader = Files.newBufferedReader(
                repository.open(tree.getPath(), org.eclipse.jgit.lib.FileMode.TEXT))) {
            return reader.lines().collect(Collectors.joining("\n"));
        } catch (Exception e) {
            return null;
        }
    }

    private static String formatDate(org.eclipse.jgit.revwalk.RevCommit commit) {
        try {
            java.util.Date date = new java.util.Date(commit.getCommit().getCommitterIdent().getLastModified());
            return java.text.SimpleDateFormat.getDateTimeInstance(
                java.text.DateFormat.LONG, 
                java.text.DateFormat.MEDIUM).format(date);
        } catch (Exception e) {
            return "Unknown";
        }
    }

    public static void main(String[] args) {
        // Demo: Create a test repository with known secrets for demonstration
        Path tempRepo = null;
        
        try {
            // Create temporary directory structure
            File baseDir = Files.createTempDirectory("pipewatch-test").toFile();
            File repoDir = new File(baseDir, "test-repo");
            repoDir.mkdirs();
            
            // Initialize git repository
            Git.init().setDirectory(repoDir).call();
            
            // Create a file with various secret patterns for testing
            File testFile = new File(repoDir, ".gitignore.example");
            Files.writeString(testFile.toPath(), 
                "// Example .gitignore with embedded secrets\n" +
                "node_modules/\n" +
                "dist/\n" +
                "# AWS credentials (BAD PRACTICE)\n" +
                "aws_secret_access_key = \"AKIAIOSFODNN7EXAMPLE\"\n" +
                "// GitHub token in config\n" +
                "[remote \"origin\"]\n" +
                "  url = https://ghp_abcdefghijklmnopqrstuvwxyz123456@github.com/user/repo.git\n");
            
            // Add and commit
            Git git = Git.open(repoDir);
            git.add().addFilepattern(".").call();
            git.commit().setMessage("Initial commit with test secrets").call();
            
            // Modify file to add more patterns
            Files.writeString(testFile.toPath(), 
                "// Example .gitignore with embedded secrets\n" +
                "node_modules/\n" +
                "dist/\n" +
                "# AWS credentials (BAD PRACTICE)\n" +
                "aws_secret_access_key = \"AKIAIOSFODNN7EXAMPLE\"\n" +
                "// GitHub token in config\n" +
                "[remote \"origin\"]\n" +
                "  url = https://ghp_abcdefghijklmnopqrstuvwxyz123456@github.com/user/repo.git\n" +
                "# Stripe key (BAD PRACTICE)\n" +
                "STRIPE_SECRET_KEY=sk_live_abc123def456ghi789jkl012mno345pqr678stu901vwx234\n");
            
            git.add().addFilepattern(".").call();
            git.commit().setMessage("Updated with more secrets").call();
            
            // Run the scanner
            System.out.println("=== Pipewatch-Pro Git Scanner Demo ===\n");
            System.out.println("Scanning repository: " + repoDir.getAbsolutePath());
            System.out.println("----------------------------------------\n");
            
            ScanResult result = scan(repoDir.toPath());
            
            // Print results
            System.out.println("Scan Summary:");
            System.out.println("  Repository: " + result.getRepositoryPath());
            System.out.println("  Commits Scanned: " + result.getTotalCommitsScanned());
            System.out.println("  Total Findings: " + result.getFindings().size());
            System.out.println("  Scan Duration: " + result.getScanDurationMs() + "ms\n");
            
            if (result.getFindings().isEmpty()) {
                System.out.println("No secrets detected!");
            } else {
                System.out.println("=== DETECTED SECRETS ===\n");
                
                // Group findings by category
                Map<String, List<SecretFinding>> grouped = result.getFindings()
                    .stream()
                    .collect(Collectors.groupingBy(f -> f.category));
                
                for (Map.Entry<String, List<SecretFinding>> entry : grouped.entrySet()) {
                    System.out.println("Category: " + entry.getKey());
                    System.out.println("  Pattern: " + entry.getValue().get(0).patternName);
                    System.out.println("  Count: " + entry.getValue().size());
                    System.out.println("  Sample: " + entry.getValue().get(0));
                    System.out.println();
                }
                
                // Severity summary
                int critical = result.getFindings().stream()
                    .filter(f -> f.category.contains("AWS") || 
                                f.category.contains("Stripe") ||
                                f.category.contains("RSA") ||
                                f.category.contains("ECDSA"))
                    .count();
                
                System.out.println("=== SEVERITY SUMMARY ===");
                System.out.println("  Critical: " + critical);
                System.out.println("  High: " + (result.getFindings().size() - critical));
            }

        } catch (Exception e) {
            System.err.println("Demo error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Cleanup
            if (tempRepo != null && tempRepo.exists()) {
                try {
                    Files.walk(tempRepo)
                        .sorted((a, b) -> Integer.compare(b.toString().length(), a.toString().length()))
                        .forEach(p -> {
                            try {
                                Files.deleteIfExists(p);
                            } catch (Exception ignored) {}
                        });
                    System.out.println("\nCleaned up temp directory: " + baseDir.getAbsolutePath());
                } catch (Exception e) {
                    System.err.println("Cleanup error: " + e.getMessage());
                }
            }
        }
    }

    // Helper to get repository from current thread context
    private static Repository repository = null;
    
    public static void setRepository(Repository repo) {
        this.repository = repo;
    }
}