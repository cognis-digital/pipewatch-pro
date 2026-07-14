#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <filesystem>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <algorithm>

namespace fs = std::filesystem;

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

const std::string TOOL_NAME = "pipewatch-pro";
const std::string VERSION = "1.0.0";
const size_t DEFAULT_MAX_COMMITS = 500;
const size_t DEFAULT_MAX_FILES = 200;
const int MAX_LINE_LENGTH = 4096;

// OWASP Top 10 patterns (simplified subset)
struct OwaspPattern {
    std::string name;
    std::regex pattern;
    std::string description;
};

std::vector<OwaspPattern> getOwaspPatterns() {
    return {
        {"Hardcoded Secret", 
         std::regex(R"(password\s*[=:]\s*['\"]?[A-Za-z0-9@#$%^&+=]{8,}['\"]?)", 
         "Potential hardcoded password"),
        
        {"SQL Injection Vector",
         std::regex(R"(\b(SELECT|UNION|INSERT|UPDATE|DELETE)\s+.*\+\s*\$|\{)",
         "Possible SQL injection point"),
         
        {"XSS Payload Pattern",
         std::regex(R"(onerror\s*=|onclick\s*=|<script[^>]*>|javascript:)",
         "Potential XSS vector"),
         
        {"Command Injection Risk",
         std::regex(R"(\b(exec|system|popen|shell_exec)\s*\(",
         "Shell command execution point"),
         
        {"Path Traversal",
         std::regex(R"(\\.\./|\.\.\\)",
         "Possible path traversal attempt")
    };
}

// ============================================================================
// UTILITY CLASSES
// ============================================================================

class TimeUtils {
public:
    static std::string formatTimestamp(const std::string& ts) {
        if (ts.empty()) return "";
        
        struct tm t;
        int year, month, day, hour, min, sec;
        
        // Try ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        if (sscanf(ts.c_str(), "%d-%d-%dT%d:%d:%d", 
                   &year, &month, &day, &hour, &min, &sec) == 6) {
            t.tm_year = year - 1900;
            t.tm_mon = month - 1;
            t.tm_mday = day;
            t.tm_hour = hour;
            t.tm_min = min;
            t.tm_sec = sec;
            t.tm_isdst = 0;
        } else {
            // Fallback to current time
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();
            t = *std::localtime(&time_t_now);
        }
        
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t);
        return std::string(buf);
    }

    static std::string formatDuration(long long ms) {
        if (ms < 1000) return std::to_string(ms) + "ms";
        double s = ms / 1000.0;
        if (s < 60) return std::to_string(s) + "s";
        double m = s / 60.0;
        if (m < 60) return std::to_string(m) + "min";
        double h = m / 60.0;
        return std::to_string(h) + "h";
    }
};

class StringUtils {
public:
    static std::string escapeHtml(const std::string& s, bool quotes = true) {
        std::string result = s;
        if (quotes) {
            result.replace(result.find('"', 0), 1, "&quot;");
            result.replace(result.find('\'', 0), 1, "&#39;");
        }
        return result;
    }

    static std::string truncate(const std::string& s, size_t maxLen, 
                                const std::string& suffix = "...") {
        if (s.length() <= maxLen) return s;
        return s.substr(0, maxLen - suffix.size()) + suffix;
    }

    static bool containsAnyCase(const std::string& haystack, 
                               const std::vector<std::string>& needles) {
        for (const auto& needle : needles) {
            if (!needle.empty() && 
                haystack.find(needle) != std::string::npos ||
                haystack.find(std::string(needle.begin(), needle.end())) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

// ============================================================================
// GIT REPOSITORY WRAPPER
// ============================================================================

class GitRepo {
private:
    std::string path_;
    bool initialized_ = false;
    
public:
    explicit GitRepo(const std::string& repoPath) : path_(repoPath) {}

    bool initialize() {
        if (!fs::exists(path_) || !fs::is_directory(path_)) {
            return false;
        }

        // Check for .git directory
        fs::path gitDir = path_ / ".git";
        if (!fs::exists(gitDir) && !fs::exists(path_ / "HEAD")) {
            return false;
        }

        initialized_ = true;
        return true;
    }

    std::string getRootPath() const {
        return path_;
    }

    // Parse HEAD to find default branch
    std::string getDefaultBranch() {
        if (!initialized_) initialize();
        
        fs::path headFile = path_ / "HEAD";
        if (fs::exists(headFile)) {
            std::ifstream file(headFile);
            std::string content;
            std::getline(file, content);
            
            // Format: ref: refs/heads/main or detached HEAD
            size_t colonPos = content.find(':');
            if (colonPos != std::string::npos) {
                return content.substr(colonPos + 2);
            }
        }
        
        return "main";
    }

    // Get list of branches
    std::vector<std::string> getBranches() {
        if (!initialized_) initialize();
        
        fs::path refsPath = path_ / ".git" / "refs" / "heads";
        std::vector<std::string> branches;
        
        if (fs::exists(refsPath)) {
            for (const auto& entry : fs::directory_iterator(refsPath)) {
                if (entry.is_regular_file()) {
                    std::ifstream file(entry.path());
                    std::string content, branchName;
                    std::getline(file, content);
                    
                    // Format: 0000000000000000000000000000000000000000\tbranch-name
                    size_t tabPos = content.find('\t');
                    if (tabPos != std::string::npos) {
                        branchName = content.substr(tabPos + 1);
                        branches.push_back(branchName);
                    }
                }
            }
        }
        
        return branches;
    }

    // Get list of tags
    std::vector<std::string> getTags() {
        if (!initialized_) initialize();
        
        fs::path refsPath = path_ / ".git" / "refs" / "tags";
        std::vector<std::string> tags;
        
        if (fs::exists(refsPath)) {
            for (const auto& entry : fs::directory_iterator(refsPath)) {
                if (entry.is_regular_file()) {
                    std::ifstream file(entry.path());
                    std::string content, tagName;
                    std::getline(file, content);
                    
                    size_t tabPos = content.find('\t');
                    if (tabPos != std::string::npos) {
                        tagName = content.substr(tabPos + 1);
                        tags.push_back(tagName);
                    }
                }
            }
        }
        
        return tags;
    }

    // Get commit log (simplified - reads from pack files)
    std::vector<CommitInfo> getCommits(size_t limit = DEFAULT_MAX_COMMITS) {
        if (!initialized_) initialize();
        
        fs::path logsPath = path_ / ".git" / "logs";
        std::vector<CommitInfo> commits;
        
        // Try to read from reflog files
        if (fs::exists(logsPath)) {
            for (const auto& entry : fs::directory_iterator(logsPath)) {
                if (entry.is_regular_file()) {
                    parseRefLog(entry.path(), commits);
                }
            }
        }
        
        // If no reflogs, try HEAD~N format parsing from packed-refs
        if (commits.empty() && fs::exists(path_ / ".git" / "packed-refs")) {
            parsePackedRefs(commits, limit);
        }
        
        return commits;
    }

private:
    struct CommitInfo {
        std::string hash;
        std::string authorName;
        std::string authorEmail;
        std::string message;
        std::string timestamp;
        int parentCount;
    };

    void parseRefLog(const fs::path& path, std::vector<CommitInfo>& commits) {
        // Format: 0000000000000000000000000000000000000000 HEAD~1 2024-01-01 12:00:00
        std::ifstream file(path);
        if (!file.is_open()) return;

        CommitInfo commit;
        while (std::getline(file, commit.hash) && commits.size() < limit) {
            // Parse timestamp
            size_t spacePos = commit.hash.find(' ');
            if (spacePos != std::string::npos) {
                std::string rest = commit.hash.substr(spacePos + 1);
                
                // Format: HEAD~1 2024-01-01 12:00:00
                size_t secondSpace = rest.find(' ');
                if (secondSpace != std::string::npos) {
                    commit.timestamp = rest.substr(secondSpace + 1);
                    
                    // Try to get message from next line or pack file
                    // For simplicity, use hash as placeholder
                    commit.message = "..." + commit.hash.substr(0, 8);
                }
                
                commits.push_back(commit);
            }
        }
    }

    void parsePackedRefs(std::vector<CommitInfo>& commits, size_t limit) {
        // This is a simplified version - real implementation would need to unpack
        fs::ifstream file(path_ / ".git" / "packed-refs");
        
        std::string line;
        while (std::getline(file, line)) {
            if (commits.size() >= limit) break;
            
            // Format: 0000000000000000000000000000000000000000\trefs/heads/main
            size_t tabPos = line.find('\t');
            if (tabPos != std::string::npos) {
                // First part is hash, second is ref
                std::string hash = line.substr(0, tabPos);
                
                CommitInfo commit;
                commit.hash = hash;
                commit.timestamp = TimeUtils::formatTimestamp("2024-01-01 00:00:00");
                commits.push_back(commit);
            }
        }
    }

    void parseRefLog(const fs::path& path, std::vector<CommitInfo>& commits) {
        // Simplified reflog parsing
        std::ifstream file(path);
        
        CommitInfo commit;
        while (std::getline(file, commit.hash)) {
            if (commit.hash.empty()) continue;
            
            // Basic timestamp extraction
            size_t firstSpace = commit.hash.find(' ');
            if (firstSpace != std::string::npos) {
                commit.timestamp = commit.hash.substr(firstSpace + 1);
                
                CommitInfo parsedCommit;
                parsedCommit.hash = commit.hash.substr(0, firstSpace);
                parsedCommit.timestamp = commit.hash.substr(firstSpace + 1);
                
                commits.push_back(parsedCommit);
            }
        }
    }
};

// ============================================================================
// COMMIT ANALYZER
// ============================================================================

class CommitAnalyzer {
private:
    GitRepo& repo_;
    
public:
    explicit CommitAnalyzer(GitRepo& r) : repo_(r) {}

    // Analyze a single commit for OWASP patterns
    std::vector<AnalysisResult> analyzeCommit(const CommitInfo& commit, 
                                              const std::string& filePath = "") {
        std::vector<AnalysisResult> results;

        // 1. Check commit message for suspicious patterns
        checkCommitMessage(commit.message, results);

        // 2. Check author information
        checkAuthorInfo(commit.authorName, commit.authorEmail, results);

        // 3. If we have a file path, scan it
        if (!filePath.empty()) {
            checkFilePath(filePath, commit.hash, results);
        }

        return results;
    }

private:
    struct AnalysisResult {
        std::string type;           // "commit", "file", "pattern"
        std::string category;       // OWASP category or analysis type
        std::string patternName;
        std::string description;
        std::string location;       // file path, commit hash, etc.
        std::string snippet;        // relevant code/text
        int severity;              // 1-5 (low to critical)
    };

    void checkCommitMessage(const std::string& message, 
                           std::vector<AnalysisResult>& results) {
        if (message.empty()) return;

        // Check for common patterns in commit messages
        const auto& patterns = getOwaspPatterns();
        
        for (const auto& pattern : patterns) {
            if (std::regex_search(message, pattern.pattern)) {
                AnalysisResult result;
                result.type = "commit";
                result.category = pattern.name;
                result.patternName = pattern.name;
                result.description = pattern.description;
                result.location = "Commit: " + commitHashShort(repo_.getDefaultBranch());
                result.severity = 2; // Medium for commit messages
                
                results.push_back(result);
            }
        }

        // Check for sensitive data in commit message
        checkSensitiveDataInMessage(message, results);
    }

    void checkAuthorInfo(const std::string& name, const std::string& email, 
                        std::vector<AnalysisResult>& results) {
        if (name.empty() && email.empty()) return;

        // Check for suspicious author patterns
        std::set<std::string> suspiciousNames = {
            "admin", "root", "system", "deploy", "ci", "cd"
        };

        for (const auto& susName : suspiciousNames) {
            if (!name.empty() && 
                name.find(susName) != std::string::npos ||
                !email.empty() && 
                email.find(susName) != std::string::npos) {
                
                AnalysisResult result;
                result.type = "author";
                result.category = "Suspicious Author Name/Email";
                result.patternName = susName;
                result.description = "Potential automated/deploy account";
                result.location = name.empty() ? email : name;
                result.severity = 1; // Low
                
                results.push_back(result);
            }
        }
    }

    void checkFilePath(const std::string& path, const std::string& commitHash, 
                      std::vector<AnalysisResult>& results) {
        if (path.empty()) return;

        // Check for sensitive file patterns
        std::set<std::string> sensitivePatterns = {
            ".env", "secrets", "credentials", "config", "settings"
        };

        bool foundSensitive = false;
        
        for (const auto& pattern : sensitivePatterns) {
            if (!path.empty() && 
                path.find(pattern) != std::string::npos ||
                path.find(std::string("." + pattern)) != std::string::npos) {
                
                AnalysisResult result;
                result.type = "file";