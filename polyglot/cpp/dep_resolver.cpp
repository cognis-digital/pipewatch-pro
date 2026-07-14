#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <ctime>
#include <memory>

namespace pipewatch {

// ============================================================================
// Data Structures
// ============================================================================

struct Dependency {
    std::string name;
    std::string version;
    std::string source;  // package.json, requirements.txt, etc.
    bool is_transitive = false;
    
    bool operator<(const Dependency& other) const {
        if (name != other.name) return name < other.name;
        return version < other.version;
    }
};

struct Vulnerability {
    std::string cve_id;
    std::string package_name;
    std::string affected_versions;  // e.g., "<1.2.3, >=1.0.0"
    std::string severity;           // LOW, MEDIUM, HIGH, CRITICAL
    std::string description;
    std::string fix_version;
};

struct AuditResult {
    std::vector<Dependency> dependencies;
    std::map<std::string, Vulnerability> vulnerabilities;
    int critical_count = 0;
    int high_count = 0;
    int medium_count = 0;
    int low_count = 0;
    double risk_score = 0.0;
    
    void add_vulnerability(const std::string& cve, const Vulnerability& v) {
        vulnerabilities[cve] = v;
        if (v.severity == "CRITICAL") critical_count++;
        else if (v.severity == "HIGH") high_count++;
        else if (v.severity == "MEDIUM") medium_count++;
        else low_count++;
    }
    
    double calculate_risk() {
        risk_score = 0.0;
        for (const auto& [cve, v] : vulnerabilities) {
            switch (v.severity[0]) {
                case 'C': risk_score += 10.0; break;
                case 'H': risk_score += 7.5; break;
                case 'M': risk_score += 4.0; break;
                default: risk_score += 1.0; break;
            }
        }
        return risk_score;
    }
};

// ============================================================================
// Embedded CVE Database (Sample)
// ============================================================================

std::vector<Vulnerability> get_cve_database() {
    static std::vector<Vulnerability> db = {
        {"CVE-2023-12345", "lodash", "<4.17.21", "HIGH", 
         "Prototype pollution in lodash before 4.17.21 allows attackers to modify object properties.", "4.17.21"},
        
        {"CVE-2023-67890", "express", "<4.18.2", "CRITICAL",
         "Path traversal vulnerability in express before 4.18.2.", "4.18.2"},
         
        {"CVE-2023-11111", "axios", "<1.6.0", "MEDIUM",
         "Cross-site request forgery in axios versions prior to 1.6.0.", "1.6.0"},
         
        {"CVE-2023-22222", "minimist", "<1.2.8", "HIGH",
         "Prototype pollution in minimist before 1.2.8.", "1.2.8"},
         
        {"CVE-2023-33333", "moment", "<2.29.4", "LOW",
         "Regular expression denial of service in moment.js.", "2.29.4"},
    };
    return db;
}

// ============================================================================
// File Parsers
// ============================================================================

class PackageJsonParser {
public:
    static AuditResult parse(const std::string& content) {
        AuditResult result;
        
        // Extract dependencies section
        std::regex deps_regex(R"(\s*"(dependencies|devDependencies)":\s*\{([^}]*)\})");
        std::smatch match;
        
        if (std::regex_search(content, match, deps_regex)) {
            std::string deps_block = match[2].str();
            
            // Parse individual dependencies
            std::regex dep_regex(R"(\s*"(\\?[^\\"]+)":\s*"([^"]+)"")");
            std::smatch dep_match;
            
            while (std::regex_search(deps_block, dep_match, dep_regex)) {
                Dependency dep;
                dep.name = dep_match[1].str();
                dep.version = dep_match[2].str();
                result.dependencies.push_back(dep);
                
                // Check for transitive marker
                if (dep.name.find("peer") != std::string::npos || 
                    dep.name.find("optional") != std::string::npos) {
                    dep.is_transitive = true;
                }
                
                std::regex_search(deps_block, dep_match, dep_regex);
            }
        }
        
        return result;
    }
};

class RequirementsParser {
public:
    static AuditResult parse(const std::string& content) {
        AuditResult result;
        
        // Parse requirements.txt format
        std::istringstream stream(content);
        std::string line;
        
        while (std::getline(stream, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') continue;
            
            Dependency dep;
            dep.source = "requirements.txt";
            
            // Extract package name
            size_t first_space = line.find(' ');
            if (first_space != std::string::npos) {
                dep.name = line.substr(0, first_space);
            } else {
                dep.name = line;
            }
            
            // Extract version from operator
            std::regex ver_regex(R"((?:==|>=|<=|~=|!=)\s*([^,\s]+))");
            std::smatch ver_match;
            
            if (std::regex_search(line, ver_match, ver_regex)) {
                dep.version = ver_match[1].str();
            } else {
                dep.version = "latest";
            }
            
            result.dependencies.push_back(dep);
        }
        
        return result;
    }
};

class PomXmlParser {
public:
    static AuditResult parse(const std::string& content) {
        AuditResult result;
        
        // Simple extraction of dependency versions from pom.xml
        std::regex dep_regex(R"(<dependency>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>)");
        std::smatch match;
        
        while (std::regex_search(content, match, dep_regex)) {
            Dependency dep;
            dep.name = match[1].str();
            dep.version = match[2].str();
            result.dependencies.push_back(dep);
            
            // Move past this match to find next
            std::string rest = content.substr(match.position() + match.length());
            if (!rest.empty()) {
                continue;
            }
        }
        
        return result;
    }
};

// ============================================================================
// Dependency Resolver Core
// ============================================================================

class DepResolver {
public:
    static AuditResult resolve(const std::string& source_file, const std::string& file_type) {
        AuditResult result;
        
        // Select parser based on file type
        if (file_type == "package.json") {
            result = PackageJsonParser::parse(source_file);
        } else if (file_type == "requirements.txt") {
            result = RequirementsParser::parse(source_file);
        } else if (file_type == "pom.xml") {
            result = PomXmlParser::parse(source_file);
        } else {
            // Auto-detect by extension
            std::string ext = source_file.substr(source_file.find_last_of('.') + 1);
            
            if (ext == "json" && !source_file.empty()) {
                result = PackageJsonParser::parse(source_file);
            } else if (ext == "txt") {
                result = RequirementsParser::parse(source_file);
            } else if (ext == "xml") {
                result = PomXmlParser::parse(source_file);
            } else {
                std::cerr << "Unknown file type: " << ext << "\n";
                return result;
            }
        }
        
        // Sort dependencies for consistent output
        std::sort(result.dependencies.begin(), result.dependencies.end());
        
        // Remove duplicates (keep first occurrence)
        auto last = std::unique(result.dependencies.begin(), result.dependencies.end());
        result.dependencies.erase(last, result.dependencies.end());
        
        return result;
    }
    
    static AuditResult resolve_from_stdin() {
        AuditResult result;
        std::string content;
        std::string line;
        
        while (std::getline(std::cin, line)) {
            content += line + "\n";
        }
        
        // Default to package.json if no file type specified
        return PackageJsonParser::parse(content);
    }
};

// ============================================================================
// Vulnerability Scanner
// ============================================================================

class VulScanner {
public:
    static void check_dependencies(const AuditResult& result, std::vector<Vulnerability>& found) {
        // Build a map of package -> versions for quick lookup
        std::map<std::string, std::set<std::string>> pkg_versions;
        
        for (const auto& dep : result.dependencies) {
            if (!dep.is_transitive) {  // Only check direct dependencies first
                pkg_versions[dep.name].insert(dep.version);
            }
        }
        
        // Check each package against CVE database
        for (const auto& [pkg, versions] : pkg_versions) {
            for (const auto& cve_db : get_cve_database()) {
                if (cve_db.package_name != pkg) continue;
                
                // Check if any installed version is affected
                bool affected = false;
                
                // Parse affected range and check each version
                std::istringstream ver_stream(cve_db.affected_versions);
                std::string ver_str;
                
                while (std::getline(ver_stream, ver_str, ',')) {
                    if (ver_str.empty()) continue;
                    
                    // Simple version comparison for demo
                    bool in_range = false;
                    
                    // Check if current version falls in affected range
                    if (cve_db.affected_versions.find("<") != std::string::npos) {
                        // Less than check
                        auto lt_pos = cve_db.affected_versions.find('<');
                        std::string limit = cve_db.affected_versions.substr(lt_pos + 1);
                        
                        if (compare_version(dep.version, limit) < 0) {
                            in_range = true;
                        }
                    } else if (cve_db.affected_versions.find(">=") != std::string::npos) {
                        // Greater or equal check
                        auto ge_pos = cve_db.affected_versions.find('>=');
                        std::string limit = cve_db.affected_versions.substr(ge_pos + 2);
                        
                        if (compare_version(dep.version, limit) >= 0) {
                            in_range = true;
                        }
                    }
                    
                    if (in_range) affected = true;
                }
                
                if (affected) {
                    found.push_back(cve_db);
                }
            }
        }
    }
    
private:
    static int compare_version(const std::string& v1, const std::string& v2) {
        // Simple semantic version comparison
        auto parse = [](const std::string& s) -> std::vector<int> {
            std::vector<int> parts;
            std::istringstream ss(s);
            std::string part;
            
            while (ss >> part) {
                if (!part.empty()) {
                    try {
                        parts.push_back(std::stoi(part));
                    } catch (...) {
                        parts.push_back(0);
                    }
                }
            }
            return parts;
        };
        
        auto v1_parts = parse(v1);
        auto v2_parts = parse(v2);
        
        // Pad shorter vector with zeros
        while (v1_parts.size() < 3) v1_parts.push_back(0);
        while (v2_parts.size() < 3) v2_parts.push_back(0);
        
        for (size_t i = 0; i < std::min(v1_parts.size(), v2_parts.size()); ++i) {
            if (v1_parts[i] < v2_parts[i]) return -1;
            if (v1_parts[i] > v2_parts[i]) return 1;
        }
        
        return 0;  // Equal
    }
};

// ============================================================================
// Report Generator
// ============================================================================

class ReportGenerator {
public:
    static std::string generate(const AuditResult& result, const std::vector<Vulnerability>& found) {
        std::ostringstream report;
        
        // Header
        time_t now = std::time(nullptr);
        char* dt = std::ctime(&now);
        *dt-- = '\0';  // Remove trailing newline
        
        report << "========================================\n";
        report << "   PIPEWATCH-PRO AUDIT REPORT\n";
        report << "========================================\n";
        report << "Generated: " << dt << "\n";
        report << "Risk Score: " << std::fixed << std::setprecision(1) 
               << result.calculate_risk() << "/10.0\n";
        report << "----------------------------------------\n";
        
        // Summary
        report << "\n## SUMMARY\n";
        report << "Total Direct Dependencies: " << result.dependencies.size() << "\n";
        report << "Vulnerabilities Found: " << found.size() << "\n";
        report << "  CRITICAL: " << result.critical_count << "\n";
        report << "  HIGH:     " << result.high_count << "\n";
        report << "  MEDIUM:   " << result.medium_count << "\n";
        report << "  LOW:      " << result.low_count << "\n";
        
        // Detailed findings
        if (!found.empty()) {
            report << "\n## DETAILED FINDINGS\n";
            report << "----------------------------------------\n\n";
            
            for (const auto& vuln : found) {
                report << "[CVE-" << vuln.cve_id << "] ";
                report << "[" << vuln.severity << "] ";
                report << vuln.package_name << "\n";
                
                if (!vuln.fix_version.empty()) {
                    report << "  Fix: Upgrade to " << vuln.fix_version << "\n";
                }
                
                report << "  Description: " << vuln.description << "\n\n";
            }
        } else {
            report << "\n## DETAILED FINDINGS\n";
            report << "----------------------------------------\n";
            report << "No vulnerabilities found in direct dependencies.\n";
            report << "Note: Transitive dependencies are not checked by default.\n";
        }
        
        // Recommendations
        if (result.risk_score > 5.0) {
            report << "\n## RECOMMENDATIONS\n";
            report << "----------------------------------------\n";
            
            if (result.critical_count > 0) {
                report << "1. URGENT: Address CRITICAL vulnerabilities within 24-48 hours.\n";
            }
            if (result.high_count > 0) {
                report << "2. HIGH: Plan fixes for HIGH severity issues this sprint.\n";
            }
            
            report << "3. Consider enabling transitive dependency scanning.\n";
            report << "4. Implement automated dependency updates in CI/CD pipeline.\n\n";
        } else {
            report << "\n## RECOMMENDATIONS\n";
            report << "----------------------------------------\n";
            report << "1. Current risk level is acceptable.\n";
            report << "2. Continue monitoring for new CVEs in active dependencies.\n";
            report << "3. Schedule quarterly dependency audits.\n\n";
        }
        
        // Footer
        report << "========================================\n";
        report << "   END OF REPORT\n";
        report << "========================================\n";
        
        return report.str();
    }
};

// ============================================================================
// Command Line Interface
// ============================================================================

class Cli {
public:
    static void print_usage() {
        std::cout << R"(
Usage: pipewatch-pro [OPTIONS] <file>

Options:
  -t, --type <TYPE>   File type (package.json|requirements.txt|pom.xml)
                      Auto-detect by extension if not specified.
  -o, --output <FILE> Write report to file instead of stdout.
  -v, --verbose       Show detailed parsing output.
  -h, --help          Show this help message.

Examples:
  pipewatch-pro package.json
  pipewatch-pro -t requirements.txt app/requirements.txt
  pipewatch-pro -o