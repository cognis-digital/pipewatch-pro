package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds scanner settings
type Config struct {
	RepoURL       string    `json:"repo_url"`
	Token         string    `json:"token,omitempty"`
	Branch        string    `json:"branch,omitempty"`
	MaxFiles      int       `json:"max_files"`
	Timeout       time.Duration
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		RepoURL:  "",
		Token:    "",
		Branch:   "main",
		MaxFiles: 1000,
		Timeout:  5 * time.Minute,
	}
}

// Result represents a single scan result
type Result struct {
	Version       string     `json:"version"`
	RepoURL       string     `json:"repo_url"`
	Branch        string     `json:"branch"`
	Summary       Summary    `json:"summary"`
	Failures      []Failure  `json:"failures,omitempty"`
	Metadata      Metadata   `json:"metadata"`
	Timestamp     time.Time  `json:"timestamp"`
}

// Summary aggregates the scan results
type Summary struct {
	TotalFiles     int       `json:"total_files"`
	TotalSizeBytes int64     `json:"total_size_bytes"`
	CriticalCount  int       `json:"critical_count"`
	HighCount      int       `json:"high_count"`
	MediumCount    int       `json:"medium_count"`
	LowCount       int       `json:"low_count"`
	DepsFound      int       `json:"deps_found"`
}

// Failure represents a single finding
type Failure struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Path        string   `json:"path"`
	RuleID      string   `json:"rule_id"`
	Message     string   `json:"message"`
	LineNumbers []int    `json:"line_numbers,omitempty"`
	CodeSnippet string   `json:"code_snippet,omitempty"`
}

// Severity defines vulnerability levels
type Severity int

const (
	SeverityCritical Severity = iota + 1
	SeverityHigh
	SeverityMedium
	SeverityLow
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// Metadata contains additional context
type Metadata struct {
	ScanDuration   time.Duration `json:"scan_duration"`
	FilesScanned   int           `json:"files_scanned"`
	GitCommit      string        `json:"git_commit,omitempty"`
	GitBranch      string        `json:"git_branch,omitempty"`
}

// OWASP patterns for common vulnerabilities
var owaspPatterns = map[string]*regexp.Regexp{
	"SQLi": {
		ID:          "OWASP-001",
		Pattern:     `(SELECT|INSERT|UPDATE|DELETE).*?(FROM|INTO|WHERE|SET).*?\(([^)]+)\)`,
		Message:     "Potential SQL injection detected in dynamic query construction",
		Severity:    SeverityHigh,
	},
	"XSS": {
		ID:          "OWASP-002",
		Pattern:     `(?i)(innerHTML|outerHTML|document\.write).*?['\"]([^'"]+)['\"]`,
		Message:     "Potential XSS vector in DOM manipulation",
		Severity:    SeverityHigh,
	},
	"Command Injection": {
		ID:          "OWASP-003",
		Pattern:     `(?i)(exec|shell_exec|system|passthru).*?\(([^)]+)\)`,
		Message:     "Potential command injection in shell execution",
		Severity:    SeverityCritical,
	},
	"Path Traversal": {
		ID:          "OWASP-004",
		Pattern:     `(?i)(fopen|file_get_contents|readfile).*?\(([^)]+)\)`,
		Message:     "Potential path traversal in file operations",
		Severity:    SeverityHigh,
	},
	"Hardcoded Secret": {
		ID:          "OWASP-005",
		Pattern:     `(?i)(password|secret|api_key|token).*?[:=]\s*['\"]([^'"]+)`,
		Message:     "Potential hardcoded secret detected",
		Severity:    SeverityCritical,
	},
}

// Scanner orchestrates the git scanning process
type Scanner struct {
	config   Config
	httpClient *http.Client
}

func NewScanner(cfg ...Config) *Scanner {
	if len(cfg) == 0 {
		cfg = append(cfg, DefaultConfig())
	}
	
	s := &Scanner{
		config:     cfg[0],
		httpClient: &http.Client{Timeout: cfg[0].Timeout},
	}
	return s
}

// Scan performs the complete git repository analysis
func (s *Scanner) Scan() (*Result, error) {
	result := &Result{
		Version:   "1.0.0",
		Timestamp: time.Now(),
		Metadata:  Metadata{},
	}
	
	if s.config.RepoURL == "" {
		return nil, fmt.Errorf("repo_url not configured")
	}

	startTime := time.Now()

	// Step 1: Fetch repository metadata and git info
	meta, err := s.fetchGitMetadata()
	if err != nil {
		return result, fmt.Errorf("failed to fetch git metadata: %w", err)
	}
	result.Metadata.GitCommit = meta.Commit
	result.Metadata.GitBranch = meta.Branch

	// Step 2: Fetch repository contents
	files, totalSize, err := s.fetchRepoContents()
	if err != nil {
		return result, fmt.Errorf("failed to fetch repo contents: %w", err)
	}
	
	result.Summary.TotalFiles = len(files)
	result.Summary.TotalSizeBytes = totalSize

	// Step 3: Analyze each file for OWASP patterns and dependencies
	failures := s.analyzeFiles(files)
	result.Failures = failures

	// Calculate summary counts
	for _, f := range failures {
		switch f.Severity {
		case SeverityCritical:
			result.Summary.CriticalCount++
		case SeverityHigh:
			result.Summary.HighCount++
		case SeverityMedium:
			result.Summary.MediumCount++
		case SeverityLow:
			result.Summary.LowCount++
		}
	}

	result.Metadata.ScanDuration = time.Since(startTime)
	return result, nil
}

// fetchGitMetadata retrieves git repository information
func (s *Scanner) fetchGitMetadata() (*struct {
	Commit string `json:"commit"`
	Branch string `json:"branch"`
}, error) {
	url := fmt.Sprintf("%s/commits/%s", s.config.RepoURL, s.config.Branch)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if s.config.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.config.Token))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return nil, fmt.Errorf("authentication failed")
	}

	body, _ := io.ReadAll(resp.Body)
	var meta struct {
		Commit string `json:"commit"`
		Branch string `json:"branch"`
	}
	
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("failed to parse git metadata: %w", err)
	}

	return &meta, nil
}

// fetchRepoContents retrieves all files from the repository
func (s *Scanner) fetchRepoContents() ([]string, int64, error) {
	// For GitHub/GitLab, use the contents API
	url := fmt.Sprintf("%s/contents?ref=%s", s.config.RepoURL, s.config.Branch)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}

	if s.config.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.config.Token))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	var items []struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Size    int64  `json:"size,omitempty"`
		Path    string `json:"path"`
		DownloadURL string `json:"download_url,omitempty"`
	}

	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, 0, fmt.Errorf("failed to parse contents: %w", err)
	}

	var files []string
	totalSize := int64(0)

	for _, item := range items {
		if len(files) >= s.config.MaxFiles {
			break
		}

		switch item.Type {
		case "file":
			files = append(files, item.Path)
			totalSize += item.Size
		case "dir":
			// Recursively fetch directory contents
			subURL := fmt.Sprintf("%s/contents/%s?ref=%s", s.config.RepoURL, item.Name, s.config.Branch)
			
			subReq, err := http.NewRequest("GET", subURL, nil)
			if err != nil {
				continue
			}

			if s.config.Token != "" {
				subReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.config.Token))
			}

			subResp, err := s.httpClient.Do(subReq)
			if err != nil {
				continue
			}
			defer subResp.Body.Close()

			var subItems []struct {
				Name    string `json:"name"`
				Type    string `json:"type"`
				Size    int64  `json:"size,omitempty"`
				Path    string `json:"path"`
			}

			subBody, _ := io.ReadAll(subResp.Body)
			if err := json.Unmarshal(subBody, &subItems); err != nil {
				continue
			}

			for _, subItem := range subItems {
				if len(files) >= s.config.MaxFiles {
					break
				}
				files = append(files, subItem.Path)
				totalSize += subItem.Size
			}
		}
	}

	return files, totalSize, nil
}

// analyzeFiles scans all fetched files for vulnerabilities and dependencies
func (s *Scanner) analyzeFiles(files []string) []Failure {
	var failures []Failure

	for _, file := range files {
		content, err := s.fetchFileContent(file)
		if err != nil {
			continue
		}

		failures = append(failures, s.scanFileContent(content, file)...)
	}

	return failures
}

// fetchFileContent retrieves the actual content of a file
func (s *Scanner) fetchFileContent(path string) ([]byte, error) {
	url := fmt.Sprintf("%s/contents/%s?ref=%s", s.config.RepoURL, path, s.config.Branch)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if s.config.Token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.config.Token))
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var item struct {
		Type    string `json:"type"`
		Path    string `json:"path"`
		DownloadURL string `json:"download_url,omitempty"`
	}

	if err := json.Unmarshal(body, &item); err != nil {
		return nil, fmt.Errorf("failed to parse file metadata: %w", err)
	}

	if item.Type == "dir" || item.DownloadURL == "" {
		return nil, fmt.Errorf("directory or missing download URL")
	}

	req2, _ := http.NewRequest("GET", item.DownloadURL, nil)
	if s.config.Token != "" {
		req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.config.Token))
	}

	resp2, err := s.httpClient.Do(req2)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()

	return io.ReadAll(resp2.Body)
}

// scanFileContent analyzes a file's content for vulnerabilities
func (s *Scanner) scanFileContent(content []byte, path string) []Failure {
	var failures []Failure
	
	fileStr := string(content)
	lines := strings.Split(fileStr, "\n")

	// Check against OWASP patterns
	for ruleName, pattern := range owaspPatterns {
		matches := pattern.FindAllStringIndex(fileStr, -1)
		
		if len(matches) > 0 {
			lineNumbers := make([]int, 0, len(matches))
			
			for _, match := range matches {
				startLine := strings.Index(fileStr[:match[0]], "\n") / 4 + 1
				if startLine <= 0 {
					startLine = 1
				}
				lineNumbers = append(lineNumbers, startLine)
			}

			failures = append(failures, Failure{
				ID:          pattern.ID,
				Severity:    pattern.Severity,
				Path:        path,
				RuleID:      ruleName,
				Message:     pattern.Message,
				LineNumbers: lineNumbers,
			})
		}
	}

	return failures
}

// PrintResult formats and prints the scan result
func (r *Result) Print() {
	fmt.Printf("=== Pipewatch-Pro Git Scanner Report ===\n")
	fmt.Printf("Version: %s\n", r.Version)
	fmt.Printf("Repo URL: %s\n", r.RepoURL)
	fmt.Printf("Branch: %s\n", r.Branch)
	fmt.Printf("Timestamp: %s\n", r.Timestamp.Format(time.RFC3339))
	fmt.Println()

	fmt.Println("--- Summary ---")
	fmt.Printf("Total Files Scanned: %d\n", r.Summary.TotalFiles)
	fmt.Printf("Total Size: %.2f MB\n", float64(r.Summary.TotalSizeBytes)/1024/1024)
	fmt.Printf("Critical Issues: %d\n", r.Summary.CriticalCount)
	fmt.Printf("High Issues: %d\n", r.Summary.HighCount)
	fmt.Printf("Medium Issues: %d\n", r.Summary.MediumCount)
	fmt.Printf("Low Issues: %d\n", r.Summary.LowCount)
	fmt.Println()

	if len(r.Failures) > 0 {
		fmt.Println("--- Failures ---")
		
		critical := make([]Failure, 0)
		high := make([]Failure, 0)
		medium := make([]Failure, 0)
		low := make([]Failure, 0)

		for _, f := range r.Failures {
			switch f.Severity {
			case SeverityCritical:
				critical = append(critical, f)
			case SeverityHigh:
				high = append(high, f)
			case SeverityMedium:
				medium = append(medium, f)
			case SeverityLow:
				low = append(low, f)
			}
		}

		if len(critical) > 0 {
			fmt.Println("CRITICAL:")
			for _, f := range critical {
				s := truncate(f.CodeSnippet, 100)
				fmt.Printf("  [%s] %s:%d\n", f.RuleID, f.Path, f.LineNumbers[0])
				fmt.Printf("    Message: %s\n", f.Message)
				if s != "" {
					fmt.Printf("    Snippet: %s...\n", s)
				}
			}
		}

		if len(high) > 0 {
			fmt.Println("\nHIGH:")
			for _, f := range high {
				s := truncate(f.CodeSnippet, 100)
				fmt.Printf("  [%s] %s:%d\n", f.RuleID, f.Path, f.LineNumbers[0])
				fmt.Printf("    Message: %s\n", f.Message)
				if s != "" {
					fmt.Printf("    Snippet: %s...\n", s)
				}
			}
		}

		if len(medium) > 0 {
			fmt.Println("\nMEDIUM:")
			for _, f := range medium {
				s := truncate(f.CodeSnippet, 100)
				fmt.Printf("  [%s] %s:%d\n", f.RuleID, f.Path, f.LineNumbers[0])
				fmt.Printf("    Message: %s\n", f.Message)
				if s != "" {
					fmt.Printf("    Snippet: %s...\n", s