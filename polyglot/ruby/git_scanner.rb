# frozen_string_literal: true

require 'bundler'
require 'json'
require 'open3'
require 'pathname'
require 'set'
require 'time'
require 'uri'

class Pipewatch::GitScanner
  # OWASP CI/CD Top 10 patterns to scan for in commits and code
  class << self
    attr_reader :owasp_patterns, :dangerous_keywords, :common_dep_patterns
    
    def initialize(repo_path: '.', options: {})
      @repo_path = Pathname.new(repo_path)
      @options = {
        verbose: false,
        include_submodules: true,
        check_commits: true,
        check_code: true,
        **options
      }.compact
      
      # Initialize pattern sets
      @owasp_patterns = build_owasp_patterns
      @dangerous_keywords = Set.new([
        'eval', 'system', 'exec', `cat`, 'shell_exec', 
        'popen', 'spawn', 'backtick', 'cmd.exe', 
        'powershell', 'wget', 'curl', 'ncat', 'netcat'
      ].flatten)
      @common_dep_patterns = Set.new([
        'gem install', 'npm install', 'yarn add', 
        'pip install', 'cargo add', 'bundle install',
        'composer require', 'apt-get install'
      ])
    end
    
    private

    def build_owasp_patterns
      patterns = []
      
      # A01:2021 - Broken Access Control (path traversal, etc)
      patterns << /A01.*?(?:traversal|injection|bypass)/i
      
      # A02:2021 - Cryptographic Failures
      patterns << /A02.*?(?:weak|default|hardcoded|secret|key|token)/i
      
      # A03:2021 - Design Flaws
      patterns << /A03.*?(?:race|concurrency|buffer|overflow)/i
      
      # A04:2021 - External Dependencies
      patterns << /A04.*?(?:supply|chain|vendor|third-party)/i
      
      # A05:2021 - Identification & Authentication Failures
      patterns << /A05.*?(?:session|cookie|auth|login|password)/i
      
      # A06:2021 - Security Misconfiguration
      patterns << /A06.*?(?:debug|dev|verbose|log|trace)/i
      
      # A07:2021 - XSS (Cross-Site Scripting)
      patterns << /A07.*?(?:xss|script|javascript|on\w+|innerHTML)/i
      
      # A08:2021 - Insufficient Logging & Monitoring
      patterns << /A08.*?(?:log|monitor|audit|track)/i
      
      # A09:2021 - Security Logging and Monitoring Failures
      patterns << /A09.*?(?:silent|quiet|suppress|capture)/i
      
      # A10:2021 - Server-Side Request Forgery (SSRF)
      patterns << /A10.*?(?:ssrf|fetch|request|curl|wget)/i
      
      Set.new(patterns.compact.uniq)
    end
    
    def run_scan
      results = {
        repo_path: @repo_path.to_s,
        scan_time: Time.now.iso8601,
        version: Pipewatch::GitScanner::VERSION,
        summary: {},
        details: {}
      }
      
      if !@repo_path.exist?
        results[:errors] = ["Repository not found: #{@repo_path}"]
        return results
      end
      
      # Check if it's a git repository
      unless @repo_path.join('.git').exist? || 
             @repo_path.join('HEAD').readable?
        results[:warnings] << "May not be a valid Git repository"
      else
        run_git_metadata_scan(results)
        run_commit_analysis(results) if @options[:check_commits]
        run_code_analysis(results) if @options[:check_code]
      end
      
      # Generate summary
      results[:summary] = build_summary(results)
      
      results
    rescue StandardError => e
      results[:errors] << "Scan failed: #{e.message}"
      results[:error_backtrace] = e.backtrace.first(10).join("\n")
      results
    end
    
    def run_git_metadata_scan(results)
      begin
        # Get basic repo info
        output, _status, _err = Open3.capture3('git', 'rev-parse', '--show-toplevel')
        
        if $?.success? && output.strip != @repo_path.to_s
          results[:metadata] = {
            root: output.strip,
            branch: `git rev-parse --abbrev-ref HEAD`.strip,
            commit: `git rev-parse --short HEAD`.strip,
            author: `git log -1 --format='%an'`.strip,
            date: `git log -1 --format='%ad' --date=iso8601`.strip,
            total_commits: `git rev-list --count HEAD`.to_i
          }
        end
        
        # Check for submodules
        results[:metadata][:submodules] = [] if @options[:include_submodules]
        output, _status, _err = Open3.capture3('git', 'config', '--list', '-z')
        
        if $?.success? && output.include?('submodule')
          results[:metadata][:has_submodules] = true
        end
        
      rescue StandardError => e
        results[:warnings] << "Git metadata error: #{e.message}"
      end
      
      results
    end
    
    def run_commit_analysis(results)
      begin
        # Get recent commits for analysis
        commit_limit = @options.fetch(:commit_limit, 100)
        
        output, _status, _err = Open3.capture3(
          'git', 'log', "--format=%H%n%B%n%an <%ae> %ad", 
          '-n', "#{commit_limit}^..HEAD"
        )
        
        if $?.success? && !output.empty?
          commits = output.split("\n").map.with_index do |line, idx|
            next unless line.strip.length > 0
            
            # Parse commit info (simplified format)
            parts = line.split("\n")
            hash = parts[0].strip if parts[0] && !parts[0].include?('\n')
            
            {
              index: idx,
              hash: hash&.strip,
              message: parts[1..-2]&.join("\n").strip,
              author: parts[-1]&.split(' ').first,
              email: parts[-1]&.include?('<') ? 
                parts[-1].match(/<([^>]+)>/) ? Regexp.last_match(1).strip : nil : nil,
              date: Time.now.iso8601 # Simplified
            }
          end.compact.reject { |c| c[:hash].nil? }
        
        results[:commits] = commits
        
        # Analyze each commit for OWASP patterns
        if @options[:check_commits] && !@owasp_patterns.empty?
          analyze_commits_for_owasp(commits, results)
        end
        
      rescue StandardError => e
        results[:warnings] << "Commit analysis error: #{e.message}"
      end
      
      results
    end
    
    def run_code_analysis(results)
      begin
        # Scan codebase for dangerous patterns and dependencies
        files_scanned = 0
        lines_scanned = 0
        
        # Find relevant source files
        extensions = ['rb', 'js', 'ts', 'py', 'java', 'c', 'h', 'php', 'go']
        
        output, _status, _err = Open3.capture3(
          'git', 'ls-files', '-z'
        )
        
        if $?.success? && !output.empty?
          files = output.split("\0").reject { |f| f.include?('node_modules') || 
                                                    f.include?('vendor') }
          
          # Limit for performance
            max_files = @options.fetch(:max_files, 500)
            files = files.first(max_files) if files.length > max_files
            
        results[:metadata][:files_scanned] = files.length
        
        # Analyze each file
        files.each do |file|
          next unless file.include?('.') && !file.start_with?('.')
          
          full_path = @repo_path.join(file)
          next unless full_path.exist?
          
            begin
              content = File.read(full_path, encoding: 'UTF-8')
              lines_scanned += 1
              
              # Check for OWASP patterns in code
              if @options[:check_code] && !@owasp_patterns.empty?
                analyze_file_for_owasp(content, file, results)
              end
              
              # Extract dependencies from comments and imports
              extract_dependencies(content, file, results)
              
            rescue StandardError => e
              next unless e.is_a?(ArgumentError) || e.is_a?(EncodingError)
              results[:warnings] << "File error: #{file} - #{e.message}"
            end
            
          files_scanned += 1
        end
        
      rescue StandardError => e
        results[:warnings] << "Code analysis error: #{e.message}"
      end
      
      results
    end
    
    def analyze_commits_for_owasp(commits, results)
      commit_issues = []
      
      commits.each do |commit|
        next unless commit[:message] && !commit[:message].empty?
        
        # Check message for OWASP patterns
        @owasp_patterns.each do |pattern|
          if pattern.match?(commit[:message])
            issue = {
              type: 'OWASP Pattern',
              file: nil,
              line: nil,
              commit_hash: commit[:hash],
              commit_message: commit[:message].strip(200),
              pattern: pattern.source,
              severity: 'medium'
            }
            
            # Determine severity based on pattern type
            if /A01|A04/i.match?(pattern) || /traversal|injection/i.match?(commit[:message])
              issue[:severity] = 'high'
            elsif /A02|A05|A07/i.match?(pattern)
              issue[:severity] = 'medium'
            end
            
            commit_issues << issue
          end
        end
        
        # Check for dangerous keywords in message
        if @dangerous_keywords.any? { |kw| commit[:message].include?(kw) }
          issue = {
            type: 'Dangerous Keyword',
            file: nil,
            line: nil,
            commit_hash: commit[:hash],
            commit_message: commit[:message].strip(200),
            keyword: @dangerous_keywords.first,
            severity: 'low'
          }
          
          commit_issues << issue if !commit_issues.any? { |i| i[:keyword] == issue[:keyword] }
        end
      end
      
      results[:details][:owasp_commit_findings] = commit_issues unless commit_issues.empty?
    end
    
    def analyze_file_for_owasp(content, filename, results)
      return if content.length > 50_000 # Performance limit
      
      file_issues = []
      
      @owasp_patterns.each do |pattern|
        matches = pattern.scan(content).flatten.compact.uniq
        next unless matches.any?
        
        issue = {
          type: 'OWASP Pattern',
          file: filename,
          line: nil, # Would need more parsing for exact lines
          commit_hash: nil,
          commit_message: nil,
          pattern: pattern.source,
          severity: 'medium'
        }
        
        issue[:severity] = 'high' if /A01|A04|A07/i.match?(pattern) || 
                                    matches.any? { |m| m.include?('eval') || m.include?('system') }
        
        file_issues << issue
      end
      
      # Check for hardcoded secrets (simplified)
      secret_patterns = [
        /(?i)(password|secret|api_key|token).*[:=]\s*['"][^'"]{4,}['"]/i,
        /(?i)(private.*key|ssl.*cert|pem).*\s*['"][^'"]{8,}['"]/i
      ]
      
      secret_patterns.each do |pattern|
        if pattern.match?(content)
          issue = {
            type: 'Potential Hardcoded Secret',
            file: filename,
            line: nil,
            commit_hash: nil,
            commit_message: nil,
            pattern: pattern.source,
            severity: 'high'
          }
          
          file_issues << issue
        end
      end
      
      results[:details][:owasp_file_findings] ||= []
      results[:details][:owasp_file_findings].concat(file_issues) unless file_issues.empty?
    end
    
    def extract_dependencies(content, filename, results)
      dep_patterns = [
        /gem\s+['"]([^'"]+)['"]/i,           # Ruby gems
        /require\s*['"]([^'"]+)['"]/i,       # Ruby requires
        /import\s+['"]([^'"]+)['"]/i,        # Python/JS imports
        /from\s+['"]([^'"]+)['"]/i,          # Python from
        /use\s+['"]([^'"]+)['"]/i            # JS use statements
      ]
      
      found_deps = []
      
      dep_patterns.each do |pattern|
        matches = pattern.scan(content).flatten.compact.uniq
        next unless matches.any?
        
        matches.each do |match|
          next if match.length < 3 || match.include?('..')
          
          # Skip common stdlib/stdlib modules
          skip_prefixes = ['bundler', 'rails', 'action', 'active', 
                          'json', 'yaml', 'date', 'time', 'uri']
          
          next if skip_prefixes.any? { |p| match.start_with?(p) }
          
          found_deps << match.strip
        end
      end
      
      results[:details][:dependencies] ||= []
      results[:details][:dependencies].concat(found_deps) unless found_deps.empty?
    end
    
    def build_summary(results)
      summary = {
        total_files: results[:metadata]&.fetch(:files_scanned, 0),
        total_commits: results[:metadata]&.fetch(:total_commits, 0),
        owasp_findings: 0,
        dependency_findings: 0,
        high_severity: 0,
        medium_severity: 0,
        low_severity: 0
      }
      
      # Count findings by severity
      all_findings = []
      
      results[:details].each do |key, value|
        next unless key.start_with?('owasp') || key == 'dependencies'
        
        if value.is_a?(Array)
          all_findings.concat(value)
        elsif value.respond_to?(:values_at)
          all_findings.concat(value.values_at('file', 'commit_hash').compact.flatten.compact.uniq)
        end
      end
      
      # Count by severity
      all_findings.each do |finding|
        next unless finding.is_a?(Hash) && finding[:severity]
        
        summary[finding[:severity].to_s + '_severity'] += 1 if ['high', 'medium', 'low'].include?(finding[:severity])
        summary[:owasp_findings] += 1
      end
      
      # Count dependencies (unique)
      deps = results[:details]&.fetch(:dependencies, []) || []
      unique_deps = deps.uniq.length
      summary[:dependency_findings] = unique_deps
      
      summary
    end
    
    def self::VERSION
      '0.1.0'
    end
  end

# Demo/Entry Point
if __FILE__ == $PROGRAM_NAME
  require 'colorize'
  
  puts "Pipewatch Pro - Git Scanner".magenta.bold
  puts "=" * 50
  
  # Default: scan current directory if no argument provided
  repo_path = ARGV.first || '.'
  
  scanner = Pipewatch::GitScanner.new(repo_path: repo_path, options: {
    verbose: true,
    commit_limit: 50
  })
  
  puts "Scanning: #{repo_path}".cyan
  
  results = scanner.run_scan
  
  # Output summary
  if results[:errors]
    puts "\nErrors:".red.bold
    results[:errors].each { |e| puts "  - #{e}" }
  end
  
  if results[:warnings]
    puts "\nWarnings:".yellow.bold
    results[:warnings].first(5).each { |w| puts "  - #{w}" }
  end
  
  summary = results[:summary]
  
  puts "\nScan Summary".green.bold
  puts "-" * 30
  
  puts "Files scanned:     #{summary[:total_files]}"
  puts "Commits analyzed:  #{summary[:total_commits]}"
  puts "OWASP findings:    #{summary[:owasp_findings]}"
  puts "Dependencies found: #{summary[:dependency_findings]}"
  puts "High severity:     #{summary[:high_severity] || 0}"
  puts "Medium severity:   #{summary[:medium_severity] || 0}"
  puts "Low severity:      #{summary[:low_severity] || 0}"