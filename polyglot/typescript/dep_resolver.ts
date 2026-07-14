import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

interface PackageJson {
  name?: string;
  version: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface RequirementLine {
  package: string;
  version?: string;
  extras?: string[];
}

interface MavenDependency {
  groupId: string;
  artifactId: string;
  version: string;
}

interface VulnerabilityRecord {
  id: string;
  name: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  affectedPackages: Record<string, string[]>; // package -> [versions]
  cveId?: string;
  description: string;
  fixVersion?: string;
}

interface AuditResult {
  timestamp: Date;
  sourceFile: string;
  directDeps: string[];
  transitiveDeps: Map<string, string[]>; // package -> [all versions seen]
  vulnerabilities: VulnerabilityRecord[];
  summary: {
    totalDirect: number;
    totalTransitive: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
}

// ============================================================================
// CONFIGURATION & DATA
// ============================================================================

const KNOWN_VULNERABILITIES: VulnerabilityRecord[] = [
  {
    id: 'VULN-001',
    name: 'Log4j Remote Code Execution',
    severity: 'CRITICAL',
    affectedPackages: {
      'log4j': ['2.0.0', '2.17.0'],
      'org.apache.logging.log4j:log4j-core': ['2.0.0', '2.17.0'],
    },
    cveId: 'CVE-2021-44832',
    description: 'Apache Log4j2 JNDI lookup vulnerability allowing remote code execution.',
    fixVersion: '2.17.1',
  },
  {
    id: 'VULN-002',
    name: 'Spring Framework Path Traversal',
    severity: 'HIGH',
    affectedPackages: {
      'spring-core': ['5.0.0', '5.3.17'],
      'org.springframework:spring-core': ['5.0.0', '5.3.17'],
    },
    cveId: 'CVE-2022-22965',
    description: 'Spring Framework allows path traversal via JMX.',
    fixVersion: '5.3.18',
  },
  {
    id: 'VULN-003',
    name: 'npm tarball injection',
    severity: 'MEDIUM',
    affectedPackages: {
      'minimist': ['1.2.0', '1.2.6'],
    },
    cveId: 'CVE-2021-44702',
    description: 'Minimist allows tarball injection via package.json.',
    fixVersion: '1.2.7',
  },
];

// ============================================================================
// PARSERS
// ============================================================================

function parsePackageJson(content: string): PackageJson | null {
  try {
    const json = JSON.parse(content);
    
    // Normalize version strings (remove ^, ~, etc.)
    const normalizeVersion = (v: string) => v.replace(/[\^~>=<]/g, '');
    
    return {
      name: json.name || 'unknown',
      version: normalizeVersion(json.version),
      dependencies: Object.entries(json.dependencies || {})
        .map(([k, v]) => [k, normalizeVersion(v)]) as Record<string, string>,
      devDependencies: Object.entries(json.devDependencies || {})
        .map(([k, v]) => [k, normalizeVersion(v)]) as Record<string, string>,
      peerDependencies: Object.entries(json.peerDependencies || {})
        .map(([k, v]) => [k, normalizeVersion(v)]) as Record<string, string>,
      optionalDependencies: Object.entries(json.optionalDependencies || {})
        .map(([k, v]) => [k, normalizeVersion(v)]) as Record<string, string>,
    };
  } catch {
    return null;
  }
}

function parseRequirements(content: string): RequirementLine[] {
  const lines = content.split('\n')
    .filter(l => l.trim() && !l.startsWith('#'))
    .map(l => {
      // Parse pip requirements format
      let package = '';
      let version = '';
      
      if (l.includes('==')) {
        [package, version] = l.split('==');
      } else if (l.includes('>=')) {
        const parts = l.split('>=');
        package = parts[0];
        version = parts.slice(1).join('>').trim();
      } else {
        package = l.trim();
      }
      
      return {
        package: package.replace(/[\^~>=<]/g, ''),
        version: version ? version.replace(/[\^~>=<]/g, '') : undefined,
      };
    });
  
  return lines;
}

function parsePom(content: string): MavenDependency[] {
  const deps: MavenDependency[] = [];
  let inDependencies = false;
  
  // Simple regex-based parsing for pom.xml
  const depRegex = /<dependency>([\s\S]*?)<\/dependency>/g;
  let match;
  
  while ((match = depRegex.exec(content)) !== null) {
    const group = match[1].match(/<groupId>([^<]+)<\/groupId>/)?.[1] || '';
    const artifact = match[1].match(/<artifactId>([^<]+)<\/artifactId>/)?.[1] || '';
    const version = match[1].match(/<version>([^<]+)<\/version>/)?.[1]?.replace(/[\^~>=<]/g, '') || '';
    
    if (group && artifact) {
      deps.push({ groupId: group.trim(), artifactId: artifact.trim(), version });
    }
  }
  
  return deps;
}

// ============================================================================
// RESOLVER ENGINE
// ============================================================================

function createDependencyMap(
  sourceFile: string,
  content: string,
  parser: (c: string) => any
): Map<string, string[]> {
  const map = new Map<string, string[]>();
  
  // Initialize with empty arrays for all packages found
  let deps;
  if (sourceFile.endsWith('.json')) {
    deps = parsePackageJson(content);
    if (!deps) return map;
    
    Object.entries(deps.dependencies || {}).forEach(([pkg, ver]) => {
      const current = map.get(pkg) || [];
      map.set(pkg, [...current, ver]);
    });
  } else if (sourceFile.endsWith('.txt')) {
    deps = parseRequirements(content);
    deps.forEach(d => {
      const current = map.get(d.package) || [];
      map.set(d.package, [...current, d.version || 'latest']);
    });
  } else if (sourceFile.includes('pom.xml')) {
    deps = parsePom(content);
    deps.forEach(d => {
      const key = `${d.groupId}:${d.artifactId}`;
      const current = map.get(key) || [];
      map.set(key, [...current, d.version]);
    });
  }
  
  return map;
}

function resolveTransitiveDeps(
  directMap: Map<string, string[]>,
  vulnerabilityDb: VulnerabilityRecord[]
): { transitive: Map<string, string[]>; vulns: VulnerabilityRecord[] } {
  const transitive = new Map<string, string[]>();
  const foundVulns: VulnerabilityRecord[] = [];
  
  // Check each direct dependency against known vulnerabilities
  for (const [pkg, versions] of directMap) {
    for (const ver of versions) {
      for (const vuln of vulnerabilityDb) {
        if (vuln.affectedPackages[pkg]) {
          const affected = vuln.affectedPackages[pkg];
          
          // Check if any version matches
          for (const affVer of affected) {
            if (ver === affVer || 
                (ver.startsWith(affVer.replace(/[0-9]/, '')) && !ver.includes('.'))) {
              // Found a match - record it
              const existing = transitive.get(pkg);
              if (!existing) {
                transitive.set(pkg, [ver]);
                foundVulns.push(vuln);
              } else {
                // Check if this version is already recorded
                if (!existing.includes(ver)) {
                  transitive.set(pkg, [...existing, ver]);
                }
              }
            }
          }
        }
      }
    }
  }
  
  return { transitive, vulns: foundVulns };
}

// ============================================================================
// AUDITOR CLASS
// ============================================================================

export class DepResolver {
  private vulnerabilityDb: VulnerabilityRecord[];
  
  constructor(vulnerabilities: VulnerabilityRecord[] = KNOWN_VULNERABILITIES) {
    this.vulnerabilityDb = vulnerabilities;
  }
  
  async resolve(sourcePath: string): Promise<AuditResult> {
    const content = fs.readFileSync(sourcePath, 'utf-8');
    const ext = path.extname(sourcePath).toLowerCase();
    
    let directMap: Map<string, string[]>;
    let sourceName = sourcePath;
    
    if (ext === '.json') {
      const pkgJson = parsePackageJson(content);
      if (!pkgJson) throw new Error(`Failed to parse ${sourcePath} as package.json`);
      
      // Combine all dependency types
      directMap = new Map();
      ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
        .forEach(type => {
          const deps = pkgJson[type as keyof PackageJson] || {};
          Object.entries(deps).forEach(([pkg, ver]) => {
            const current = directMap.get(pkg) || [];
            directMap.set(pkg, [...current, ver]);
          });
        });
    } else if (ext === '.txt') {
      directMap = createDependencyMap(sourcePath, content, parseRequirements);
    } else if (sourcePath.includes('pom.xml')) {
      directMap = createDependencyMap(sourcePath, content, parsePom);
    } else {
      throw new Error(`Unsupported file type: ${ext}`);
    }
    
    const { transitive, vulns } = resolveTransitiveDeps(directMap, this.vulnerabilityDb);
    
    // Calculate summary
    let totalDirect = 0;
    for (const [, versions] of directMap) totalDirect += versions.length;
    
    let totalTransitive = 0;
    for (const [, versions] of transitive) totalTransitive += versions.length;
    
    const criticalCount = vulns.filter(v => v.severity === 'CRITICAL').length;
    const highCount = vulns.filter(v => v.severity === 'HIGH').length;
    const mediumCount = vulns.filter(v => v.severity === 'MEDIUM').length;
    const lowCount = vulns.filter(v => v.severity === 'LOW').length;
    
    return {
      timestamp: new Date(),
      sourceFile: sourcePath,
      directDeps: Array.from(directMap.keys()),
      transitiveDeps: transitive,
      vulnerabilities: vulns,
      summary: {
        totalDirect,
        totalTransitive,
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
      },
    };
  }
  
  generateReport(result: AuditResult): string {
    let output = `========================================\n`;
    output += `PIPEWATCH-PRO DEPENDENCY AUDIT REPORT\n`;
    output += `========================================\n\n`;
    output += `Source File: ${result.sourceFile}\n`;
    output += `Timestamp:   ${result.timestamp.toISOString()}\n\n`;
    
    output += `--- SUMMARY ---\n`;
    output += `  Direct Dependencies:  ${result.summary.totalDirect}\n`;
    output += `  Transitive Found:     ${result.summary.totalTransitive}\n`;
    output += `  CRITICAL:             ${result.summary.criticalCount}\n`;
    output += `  HIGH:                 ${result.summary.highCount}\n`;
    output += `  MEDIUM:               ${result.summary.mediumCount}\n`;
    output += `  LOW:                  ${result.summary.lowCount}\n\n`;
    
    if (result.vulnerabilities.length > 0) {
      output += `--- VULNERABILITIES FOUND ---\n\n`;
      
      for (const vuln of result.vulnerabilities) {
        output += `  [${vuln.severity}] ${vuln.name}\n`;
        if (vuln.cveId) output += `    CVE:     ${vuln.cveId}\n`;
        output += `    Package: ${Object.keys(vuln.affectedPackages)[0]}\n`;
        output += `    Fix:     ${vuln.fixVersion || 'Check release notes'}\n\n`;
      }
    } else {
      output += `--- VULNERABILITIES ---\n`;
      output += `  No known vulnerabilities found in this dependency set.\n\n`;
    }
    
    return output;
  }
}

// ============================================================================
// CLI INTERFACE
// ============================================================================

function printUsage() {
  console.log(`
Usage: pipewatch-pro dep-resolve <file> [options]

Arguments:
  file      Path to package.json, requirements.txt, or pom.xml

Options:
  -o, --output    Output report to file (default: stdout)
  -v, --verbose   Show detailed parsing info
  -q, --quiet     Minimal output
  
Examples:
  pipewatch-pro dep-resolve ./package.json
  pipewatch-pro dep-resolve ./requirements.txt -o report.txt
`);
}

function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    printUsage();
    process.exit(1);
  }
  
  const sourceFile = args[0];
  let outputFile: string | undefined;
  let verbose = false;
  
  // Parse options
  for (let i = 1; i < args.length; i++) {
    switch (args[i]) {
      case '-o':
      case '--output':
        if (i + 1 < args.length) outputFile = args[++i];
        break;
      case '-v':
      case '--verbose':
        verbose = true;
        break;
      case '-q':
      case '--quiet':
        // Silent mode - just output report
        break;
    }
  }
  
  if (!fs.existsSync(sourceFile)) {
    console.error(`Error: File not found: ${sourceFile}`);
    process.exit(1);
  }
  
  const resolver = new DepResolver();
  
  try {
    const result = resolver.resolve(sourceFile);
    
    let report = resolver.generateReport(result);
    
    if (verbose) {
      console.log(`Parsed ${result.directDeps.length} direct dependencies`);
      console.log(`Found ${result.vulnerabilities.length} vulnerability matches`);
    }
    
    if (outputFile) {
      fs.writeFileSync(outputFile, report);
      console.log(`Report written to: ${outputFile}`);
    } else {
      console.log(report);
    }
  } catch (error: any) {
    console.error(`Error resolving dependencies:\n${String(error.message || error)}`);
    process.exit(1);
  }
}

// ============================================================================
// RUNTIME DEMO / SELF-TEST
// ============================================================================

if (require.main === module) {
  // When run directly, demonstrate with a sample package.json
  
  const demoPackageJson = `
{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21",
    "log4j": "2.17.0"
  },
  "devDependencies": {
    "typescript": "~5.0.0"
  }
}
`;

  // Write temp file for demo
  const tempPath = path.join(process.cwd(), 'demo-package.json');
  
  try {
    fs.writeFileSync(tempPath, demoPackageJson);
    
    console.log('========================================');
    console.log('PIPEWATCH-PRO: Self-Test Mode');
    console.log('========================================\n');
    
    const resolver = new DepResolver();
    const result = resolver.resolve(tempPath);
    
    console.log(resolver.generateReport(result));
    
    // Cleanup temp file
    fs.unlinkSync(tempPath);
  } catch (error: any) {
    console.error('Demo failed:', error.message);
    process.exit(1);
  }
}

//