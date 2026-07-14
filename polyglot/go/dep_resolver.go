package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
)

// Package represents a resolved dependency with metadata
type Package struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Src        string    `json:"source,omitempty"`
	Checksum   string    `json:"checksum,omitempty"`
	ResolvedAt time.Time `json:"resolved_at"`
}

// Vulnerability represents a known CVE for a package
type Vulnerability struct {
	CVEID       string      `json:"cve_id"`
	Package     string      `json:"package"`
	Version     string      `json:"version"`
	SemverRange *semver.Constraints
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
}

// ResolverConfig holds configuration for the resolver
type ResolverConfig struct {
	CacheDir         string
	Timeout          time.Duration
	VulnDBPath       string
	Thresholds       Thresholds
}

// Thresholds defines severity thresholds
type Thresholds struct {
	High    int // max allowed high severity vulns
	Medium  int // max allowed medium severity vulns
	Low     int // max allowed low severity vulns
}

// Report represents the final audit report
type AuditReport struct {
	ResolvedPackages []Package      `json:"resolved_packages"`
	Vulnerabilities  []Vulnerability `json:"vulnerabilities,omitempty"`
	Metadata         Metadata        `json:"metadata"`
	Summary          Summary         `json:"summary"`
}

// Metadata contains resolution metadata
type Metadata struct {
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	Duration     string    `json:"duration_ms"`
	TotalPackages int       `json:"total_packages"`
	UniqueSources map[string]struct{}
}

// Summary provides quick stats
type Summary struct {
	TotalVulns   int  `json:"total_vulnerabilities"`
	Critical     int  `json:"critical"`
	High         int  `json:"high"`
	Medium       int  `json:"medium"`
	Low          int  `json:"low"`
	RiskScore    float64 `json:"risk_score"`
}

// Common lock file parsers
var lockFileParsers = map[string]func(string) ([]Package, error){
	"go.mod":      parseGoMod,
	"package-lock.json": parseNPMLock,
	"yarn.lock":   parseYarnLock,
	"Pipfile.lock": parsePipLock,
	"Gemfile.lock": parseGemLock,
}

// Common manifest parsers (for non-locked states)
var manifestParsers = map[string]func(string) ([]Package, error){
	"go.mod":      parseGoModManifest,
	"package.json": parseNPMManifest,
	"requirements.txt": parsePyPIManifest,
	"Gemfile":     parseGemManifest,
}

// Thresholds for default config
var DefaultThresholds = Thresholds{
	High:    0,
	Medium:  5,
	Low:     20,
}

func NewResolver(cfg *ResolverConfig) *Resolver {
	if cfg == nil {
		cfg = &ResolverConfig{}
	}
	
	if cfg.CacheDir == "" {
		cacheDir := filepath.Join(os.Getenv("HOME"), ".pipewatch", "cache")
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: using temp cache: %v\n", err)
			cfg.CacheDir = "/tmp/pipewatch"
		} else {
			cfg.CacheDir = cacheDir
		}
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	return &Resolver{
		Config:   *cfg,
		parsers:  lockFileParsers,
		metadata: make(map[string]Metadata),
	}
}

// Resolver handles dependency resolution and auditing
type Resolver struct {
	Config   ResolverConfig
	parsers  map[string]func(string) ([]Package, error)
	metadata map[string]Metadata
	mu       sync.Mutex
}

// Resolve performs the full dependency resolution pipeline
func (r *Resolver) Resolve(projectPath string) (*AuditReport, error) {
	start := time.Now()
	
	// Step 1: Discover and parse lock files
	packages, err := r.discoverLockFiles(projectPath)
	if err != nil {
		return nil, fmt.Errorf("discovering lock files: %w", err)
	}

	// Step 2: Resolve any unresolved versions
	resolved, err := r.resolveVersions(packages, projectPath)
	if err != nil {
		return nil, fmt.Errorf("resolving versions: %w", err)
	}

	// Step 3: Check for supply-chain anomalies
	anomalies, err := r.checkAnomalies(resolved, projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning during anomaly check: %v\n", err)
	}

	// Step 4: Resolve transitive dependencies (simplified - real impl would use registry API)
	transitive := r.resolveTransitiveDependencies(resolved, projectPath)

	// Deduplicate and sort
	allPackages := deduplicateAndSort(transitive)

	// Step 5: Check vulnerabilities (would integrate with NVD/Snyk/Dependabot APIs)
	vulns := r.checkVulnerabilities(allPackages)

	// Build report
	report := &AuditReport{
		ResolvedPackages: allPackages,
		Vulnerabilities:  vulns,
		Metadata: Metadata{
			StartTime:    start,
			EndTime:      time.Now(),
			Duration:     fmt.Sprintf("%d", int64(time.Since(start).Milliseconds())),
			TotalPackages: len(allPackages),
			UniqueSources: make(map[string]struct{}),
		},
		Summary: Summary{
			Critical: 0,
			High:     0,
			Medium:   0,
			Low:      0,
		},
	}

	// Calculate summary stats
	for _, v := range vulns {
		switch strings.ToLower(v.Severity) {
		case "critical":
			report.Summary.Critical++
		case "high":
			report.Summary.High++
		case "medium":
			report.Summary.Medium++
		case "low":
			report.Summary.Low++
		}

		if _, ok := report.Metadata.UniqueSources[v.Src]; !ok {
			report.Metadata.UniqueSources[v.Src] = struct{}{}
		}
	}

	return report, nil
}

// discoverLockFiles finds and parses all lock files in the project
func (r *Resolver) discoverLockFiles(projectPath string) ([]Package, error) {
	var packages []Package
	
	// Look for common lock file names
	lockNames := []string{
		"go.mod", "package-lock.json", "yarn.lock", 
		"Pipfile.lock", "Gemfile.lock", "Cargo.toml",
	}

	for _, name := range lockNames {
		fullPath := filepath.Join(projectPath, name)
		if exists, _ := fileExists(fullPath); !exists {
			continue
		}

		parser, ok := r.parsers[name]
		if !ok {
			fmt.Fprintf(os.Stderr, "No parser for %s\n", name)
			continue
		}

		pkgs, err := parser(fullPath)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}

		for i := range pkgs {
			pkgs[i].ResolvedAt = time.Now()
		}

		packages = append(packages, pkgs...)
	}

	if len(packages) == 0 {
		return nil, fmt.Errorf("no lock files found in %s", projectPath)
	}

	return packages, nil
}

// resolveVersions ensures all versions are properly resolved (including semver ranges)
func (r *Resolver) resolveVersions(packages []Package, projectPath string) ([]Package, error) {
	resolved := make([]Package, 0, len(packages))
	
	for _, pkg := range packages {
		v, err := semver.NewConstraint(pkg.Version)
		if err == nil && v != nil {
			// Extract a concrete version from the constraint
			concrete := v.Min()
			if concrete != nil {
				pkg.Version = fmt.Sprintf("%s", concrete.String())
			}
		}
		
		resolved = append(resolved, pkg)
	}

	return resolved, nil
}

// checkAnomalies looks for supply-chain attack patterns
func (r *Resolver) checkAnomalies(packages []Package, projectPath string) ([]string, error) {
	var anomalies []string
	
	for _, pkg := range packages {
		// Check for typosquatting domains
		if matchesTyposquat(pkg.Src) {
			anomalies = append(anomalies, fmt.Sprintf("possible typosquat: %s", pkg.Name))
		}

		// Check for unexpected version bumps (would need git history in real impl)
		
		// Check for known bad actors
		if matchesBadActor(pkg.Src) {
			anomalies = append(anomalies, fmt.Sprintf("known bad actor domain: %s", pkg.Name))
		}
	}

	return anomalies, nil
}

// resolveTransitiveDependencies resolves transitive dependencies (simplified)
func (r *Resolver) resolveTransitiveDependencies(packages []Package, projectPath string) []Package {
	// In a real implementation, this would:
	// 1. Query package registries for each direct dependency
	// 2. Fetch their own dependency trees
	// 3. Merge and deduplicate
	
	// For demo purposes, add some "transitive" packages
	transitive := make([]Package, len(packages))
	copy(transitive, packages)

	// Simulate finding transitive deps (in real code: registry API calls)
	for i := range transitive {
		if strings.Contains(transitive[i].Name, "lodash") || 
		   strings.Contains(transitive[i].Name, "underscore") {
			// These often have many transitive deps
			transitive = append(transitive, Package{
				Name:       fmt.Sprintf("%s-internal", transitive[i].Name),
				Version:    "1.0.0",
				Src:        "registry.npmjs.org",
				ResolvedAt: time.Now(),
			})
		}
	}

	return transitive
}

// deduplicateAndSort removes duplicates and sorts packages
func deduplicateAndSort(packages []Package) []Package {
	seen := make(map[string]bool)
	var result []Package
	
	for _, pkg := range packages {
		key := fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		if !seen[key] {
			seen[key] = true
			result = append(result, pkg)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}

// checkVulnerabilities checks packages against known vulnerabilities
func (r *Resolver) checkVulnerabilities(packages []Package) []Vulnerability {
	var vulns []Vulnerability
	
	for _, pkg := range packages {
		// Simulate vulnerability database lookup
		vulnDB, err := r.loadVulnDB()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: loading vuln DB: %v\n", err)
			continue
		}

		for _, v := range vulnDB {
			if matchesPackage(v.Package, pkg.Name) && 
			   matchesVersion(v.Version, pkg.Version) {
				
				vulns = append(vulns, Vulnerability{
					CVEID:       v.CVEID,
					Package:     v.Package,
					Version:     v.Version,
					SemverRange: v.SemverRange,
					Severity:    v.Severity,
					Description: v.Description,
				})
			}
		}
	}

	return vulns
}

// loadVulnDB loads the vulnerability database (simulated)
func (r *Resolver) loadVulnDB() ([]Vulnerability, error) {
	var db []Vulnerability
	
	// Simulated vulnerability data - in production this would come from NVD/Snyk/etc.
	db = append(db, Vulnerability{
		CVEID:       "CVE-2021-44531",
		Package:     "lodash",
		Version:     ">=4.17.0 <4.17.21",
		SemverRange: semver.MustParseConstraint(">=4.17.0 <4.17.21"),
		Severity:    "high",
		Description: "Prototype Pollution in lodash before 4.17.21",
	})

	db = append(db, Vulnerability{
		CVEID:       "CVE-2020-8203",
		Package:     "express",
		Version:     ">=4.16.0 <4.18.2",
		SemverRange: semver.MustParseConstraint(">=4.16.0 <4.18.2"),
		Severity:    "medium",
		Description: "Path traversal in express before 4.18.2",
	})

	db = append(db, Vulnerability{
		CVEID:       "CVE-2023-45807",
		Package:     "semver",
		Version:     ">=6.0.0 <7.5.2",
		SemverRange: semver.MustParseConstraint(">=6.0.0 <7.5.2"),
		Severity:    "medium",
		Description: "Regular expression DoS in semver before 7.5.2",
	})

	return db, nil
}

// matchesPackage checks if a package name matches (with partial matching)
func matchesPackage(pattern, pkg string) bool {
	patternLower := strings.ToLower(pattern)
	pkgLower := strings.ToLower(pkg)
	
	if pattern == "*" || pattern == "" {
		return true
	}
	
	if strings.Contains(pkgLower, patternLower) || 
	   strings.Contains(patternLower, pkgLower) {
		return true
	}

	return false
}

// matchesVersion checks if a version string matches the package's version
func matchesVersion(dbVer, pkgVer string) bool {
	dbVer = strings.TrimSpace(dbVer)
	pkgVer = strings.TrimSpace(pkgVer)

	if dbVer == "*" || dbVer == "" {
		return true
	}

	// Try exact match first
	if dbVer == pkgVer {
		return true
	}

	// Try semver range matching
	constraints, err := semver.NewConstraint(dbVer)
	if err != nil {
		// Fallback: try prefix matching
		return strings.HasPrefix(pkgVer, dbVer[:3])
	}

	v, err := semver.NewVersion(pkgVer)
	if err == nil && constraints.Check(v) {
		return true
	}

	return false
}

// matchesTyposquat checks for common typosquatting patterns
func matchesTyposquat(src string) bool {
	if src == "" {
		return false
	}

	srcLower := strings.ToLower(src)

	// Common typosquat patterns
	patterns := []string{
		"npmjs.org",           // "npmjss.org", "npmsjs.org"
		"cdn.jsdelivr.net",    // "cdn.jsdelivr.net"
		"github.com",          // "gitub.com", "github.io" (legit but often confused)
		"raw.githubusercontent.com",
	}

	for _, p := range patterns {
		if strings.Contains(srcLower, p) && !strings.Contains(srcLower, "_") {
			return true
		}
	}

	// Check for common misspellings of "npmjs.org"
	misspellings := []string{
		"npmsjs.org", "npm-js.org