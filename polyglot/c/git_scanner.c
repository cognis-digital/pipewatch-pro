/*
 * polyglot/c/git_scanner.c
 * 
 * pipewatch-pro: CI/CD Supply-Chain Auditor - Git Scanner Module
 * 
 * Scans git repositories for OWASP CI/CD Top 10 vulnerabilities,
 * external dependencies, submodules, and suspicious patterns.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <limits.h>

#define MAX_LINE 4096
#define MAX_PATH 1024
#define MAX_COMMITS 5000
#define MAX_FINDINGS 1000

/* Severity levels */
typedef enum {
    SEV_INFO = 0,
    SEV_LOW = 1,
    SEV_MEDIUM = 2,
    SEV_HIGH = 3,
    SEV_CRITICAL = 4
} severity_t;

/* Finding structure */
struct finding {
    char *id;
    severity_t sev;
    char *title;
    char *description;
    char *location;
    char *evidence;
    time_t timestamp;
};

#define SEV_NAMES "INFO,LOW,MEDIUM,HIGH,CRITICAL"

static const char *sev_name(severity_t s) {
    switch (s) {
        case SEV_INFO: return "INFO";
        case SEV_LOW:  return "LOW";
        case SEV_MEDIUM: return "MEDIUM";
        case SEV_HIGH:  return "HIGH";
        default: return "CRITICAL";
    }
}

/* Forward declarations */
static struct finding *findings_alloc(void);
static void findings_free(struct finding *f);
static int findings_add(struct finding **head, severity_t sev, 
                        const char *title, const char *desc,
                        const char *loc, const char *evidence);
static void print_report(const struct finding *head);

/* ============ FILE PARSER ============ */

typedef enum {
    PKG_JSON, REQ_TXT, GO_MOD, CARGO_TOML, PYPI_LOCK, NPM_LOCK,
    GEMFILE, MIXMANIFEST, MAX_MANIFEST
} manifest_type_t;

static const char *manifest_names[] = {
    "package.json", "requirements.txt", "go.mod", "Cargo.toml",
    "Pipfile.lock", "package-lock.json", "Gemfile", "mix.exs"
};

/* Parse package.json for npm dependencies */
static int parse_package_json(const char *path, struct finding **head) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Extract dependencies */
        if (strstr(line, "\"dependencies\"") || 
            strstr(line, "\"devDependencies\"")) {
            
            char *dep = strtok(line, ":");
            if (!dep) continue;
            
            /* Look for actual dependency entries */
            while ((dep = strtok(NULL, ",")) != NULL) {
                dep = strtok(dep, " \t\n\r{}[]:");
                if (dep && strlen(dep) > 0) {
                    severity_t sev = SEV_LOW;
                    
                    /* Check for known vulnerable packages */
                    const char *vuln_patterns[] = {
                        "lodash", "moment", "express", "axios",
                        "underscore", "bluebird"
                    };
                    
                    for (int i = 0; vuln_patterns[i]; i++) {
                        if (strstr(dep, vuln_patterns[i])) {
                            sev = SEV_MEDIUM;
                            break;
                        }
                    }
                    
                    findings_add(head, sev, "npm Dependency", 
                                "Found npm package: " dep,
                                path, dep);
                }
            }
        }
    }
    
    fclose(f);
    return 1;
}

/* Parse requirements.txt for pip dependencies */
static int parse_requirements_txt(const char *path, struct finding **head) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        char *p = line;
        while (*p && isspace(*p)) p++;
        if (*p == '#' || !*p) continue;
        
        severity_t sev = SEV_LOW;
        const char *vuln_patterns[] = {
            "requests", "flask", "django", "sqlalchemy"
        };
        
        for (int i = 0; vuln_patterns[i]; i++) {
            if (strstr(p, vuln_patterns[i])) {
                sev = SEV_MEDIUM;
                break;
            }
        }
        
        findings_add(head, sev, "pip Dependency", 
                    "Found pip package: " p,
                    path, p);
    }
    
    fclose(f);
    return 1;
}

/* Parse go.mod for Go dependencies */
static int parse_go_mod(const char *path, struct finding **head) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Extract module dependencies */
        if (strstr(line, "// indirect") || 
            strstr(line, "// external")) {
            
            char *dep = strtok(line, " \t\n\r/");
            if (!dep) continue;
            
            dep = strtok(dep, ",");
            while (dep && strlen(dep) > 0) {
                dep = strtok(dep, " \t\n\r/");
                if (dep && strlen(dep) > 0) {
                    findings_add(head, SEV_LOW, "Go Dependency", 
                                "Found Go module: " dep,
                                path, dep);
                }
            }
        }
    }
    
    fclose(f);
    return 1;
}

/* Parse Cargo.toml for Rust dependencies */
static int parse_cargo_toml(const char *path, struct finding **head) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Look for dependency sections */
        if (strstr(line, "[dependencies]") || 
            strstr(line, "[dev-dependencies]")) {
            
            char *dep = strtok(line, " \t\n\r");
            while (dep && strlen(dep) > 0) {
                dep = strtok(dep, ",");
                if (dep && strlen(dep) > 0) {
                    findings_add(head, SEV_LOW, "Rust Dependency", 
                                "Found Rust crate: " dep,
                                path, dep);
                }
            }
        }
    }
    
    fclose(f);
    return 1;
}

/* ============ GIT HISTORY ANALYZER ============ */

static int run_git_command(const char *repo_path, const char *cmd) {
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return -1;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), pipe)) {
        fprintf(stderr, "[GIT] %s\n", line);
    }
    
    int status = pclose(pipe);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Check for insecure git protocols */
static void check_git_protocols(const char *repo_path, struct finding **head) {
    /* Check if using git:// protocol anywhere in history */
    char cmd[PATH_MAX + 50];
    snprintf(cmd, sizeof(cmd), 
             "cd %s && git log --all -p 2>/dev/null | grep -o 'git://[^\\\"]*' | head -100",
             repo_path);
    
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), pipe)) {
        severity_t sev = SEV_MEDIUM;
        
        /* Check for git:// protocol */
        if (strstr(line, "git://")) {
            findings_add(head, sev, "Insecure Git Protocol", 
                        "Found git:// URL in repository history (may expose internal paths)",
                        repo_path, line);
        }
    }
    
    pclose(pipe);
}

/* Check for hardcoded secrets in commit messages */
static void check_commit_secrets(const char *repo_path, struct finding **head) {
    char cmd[PATH_MAX + 50];
    snprintf(cmd, sizeof(cmd), 
             "cd %s && git log --all -p 2>/dev/null | grep -oE '([A-Za-z0-9]{16,32}|sk_live_|api_key|secret|token=\\S+)' | head -50",
             repo_path);
    
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), pipe)) {
        severity_t sev = SEV_HIGH;
        
        /* Check for common secret patterns */
        const char *secret_patterns[] = {
            "sk_live_", "sk_test_", "api_key", "secret=", 
            "token=", "PRIVATE_KEY", "CERTIFICATE"
        };
        
        for (int i = 0; secret_patterns[i]; i++) {
            if (strstr(line, secret_patterns[i])) {
                findings_add(head, sev, "Potential Secret in Commit", 
                            "Found potential hardcoded secret pattern: " line,
                            repo_path, line);
                break;
            }
        }
    }
    
    pclose(pipe);
}

/* Check for submodules */
static void check_submodules(const char *repo_path, struct finding **head) {
    char cmd[PATH_MAX + 50];
    snprintf(cmd, sizeof(cmd), 
             "cd %s && git submodule status 2>/dev/null",
             repo_path);
    
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), pipe)) {
        severity_t sev = SEV_MEDIUM;
        
        /* Check for uncommitted submodule changes */
        if (strstr(line, "-") || strstr(line, "??")) {
            findings_add(head, sev, "Uncommitted Submodule", 
                        "Submodule with pending changes: " line,
                        repo_path, line);
        } else if (strlen(line) > 0 && !strchr(line, '-')) {
            /* Normal submodule - log for info */
            char *p = strchr(line, ' ');
            if (p) {
                findings_add(head, SEV_INFO, "Active Submodule", 
                            "Submodule found: " p,
                            repo_path, line);
            }
        }
    }
    
    pclose(pipe);
}

/* Check for large binary blobs in history */
static void check_large_blobs(const char *repo_path, struct finding **head) {
    char cmd[PATH_MAX + 100];
    snprintf(cmd, sizeof(cmd), 
             "cd %s && git log --all -p --numstat 2>/dev/null | grep -E '^[0-9]{4,}' | head -30",
             repo_path);
    
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return;
    
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), pipe)) {
        severity_t sev = SEV_MEDIUM;
        
        /* Check for very large additions */
        long size = atol(strtok(line, " \t"));
        if (size > 1048576) { /* 1MB threshold */
            findings_add(head, sev, "Large Binary in History", 
                        "Found file addition of " size " bytes: " line,
                        repo_path, line);
        }
    }
    
    pclose(pipe);
}

/* ============ MANIFEST SCANNER ============ */

static int scan_manifests(const char *repo_path, struct finding **head) {
    DIR *dir = opendir(repo_path);
    if (!dir) return 0;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        
        /* Check for manifest files */
        for (int i = 0; i < MAX_MANIFEST; i++) {
            if (strcmp(name, manifest_names[i]) == 0) {
                findings_add(head, SEV_INFO, "Manifest File", 
                            "Found: " name,
                            repo_path, name);
                
                /* Parse based on type */
                if (strstr(name, ".json")) {
                    parse_package_json(repo_path, head);
                } else if (strcmp(name, "requirements.txt") == 0) {
                    parse_requirements_txt(repo_path, head);
                } else if (strcmp(name, "go.mod") == 0) {
                    parse_go_mod(repo_path, head);
                } else if (strcmp(name, "Cargo.toml") == 0) {
                    parse_cargo_toml(repo_path, head);
                }
            }
        }
    }
    
    closedir(dir);
    return 1;
}

/* ============ REPORT GENERATOR ============ */

static struct finding *findings_alloc(void) {
    struct finding *f = malloc(sizeof(*f));
    if (f) {
        f->id = NULL;
        f->sev = SEV_INFO;
        f->title = NULL;
        f->description = NULL;
        f->location = NULL;
        f->evidence = NULL;
        f->timestamp = time(NULL);
    }
    return f;
}

static void findings_free(struct finding *f) {
    if (!f) return;
    
    free(f->id);
    free(f->title);
    free(f->description);
    free(f->location);
    free(f->evidence);
    free(f);
}

static int findings_add(struct finding **head, severity_t sev, 
                        const char *title, const char *desc,
                        const char *loc, const char *evidence) {
    struct finding *f = *head;
    
    if (!f || f->id) {
        f = malloc(sizeof(*f));
        if (!f) return 0;
        
        memset(f, 0, sizeof(*f));
        f->sev = sev;
        f->timestamp = time(NULL);
    } else {
        /* Reuse existing finding for same location */
        free(f->id);
        free(f->title);
        free(f->description);
        free(f->location);
        free(f->evidence);
        
        memset(f, 0, sizeof(*f));
        f->sev = sev;
    }
    
    /* Generate unique ID */
    char id[64];
    snprintf(id, sizeof(id), "%s_%ld", loc, (long)time(NULL));
    f->id = strdup(id);
    
    f->title = strdup(title);
    f->description = strdup(desc);
    f->location = strdup(loc);
    f->evidence = strdup(evidence ? evidence : "");
    
    *head = f;
    return 1;
}

static void print_report(const struct finding *head) {
    printf("\n========================================\n");
    printf("   PIPEWATCH-PRO GIT SCAN REPORT\n");
    printf("========================================\n\n");
    
    int total = 0, critical = 0, high = 0, medium = 0, low = 0, info = 0;
    
    for (const struct finding *f = head; f; f = f->next) {
        printf("[%s] %s\n", sev_name(f->sev), f->title);
        printf("  Location: %s\n", f->location ? f->location : "unknown");
        printf("  Description: %s\n", f->description ? f->description : "");
        
        if (f->evidence && strlen(f->evidence) > 0) {
            printf("  Evidence: %s\n", f->evidence);
        }
        
        total++;
        switch (f->sev) {
            case SEV_CRITICAL: critical++; break;
            case SEV_HIGH: high++; break;
            case SEV_MEDIUM: medium++; break;
            case SEV_LOW: low++; break;
            default: info++; break;
        }
    }
    
    printf("\n========================================\n");
    printf("