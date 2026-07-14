/*
 * pipewatch-pro: CI/CD Supply-Chain Auditor
 * Module: dep_resolver.c - Dependency Resolver & Analyzer
 * 
 * Parses common package formats, resolves dependencies, and detects issues.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

/* ==================== CONFIGURATION ==================== */

#define MAX_LINE_LEN 4096
#define MAX_PATH_LEN 1024
#define MAX_DEPS 8192
#define MAX_VULN_DB_SIZE 16384
#define DEFAULT_TIMEOUT_SEC 30

/* Severity levels for vulnerabilities */
typedef enum {
    SEV_UNKNOWN = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} sev_t;

/* Dependency types supported */
typedef enum {
    DEP_NPM,      /* package.json (Node.js) */
    DEP_PIP,     /* requirements.txt / pyproject.toml (Python) */
    DEP_GOPATH,  /* go.mod / go.sum (Go) */
    DEP_MAVEN,   /* pom.xml (Java/Maven) */
    DEP_RUBY,    /* Gemfile / gemspec (Ruby) */
    DEP_COMPOUND /* Composite/unknown format */
} dep_type_t;

/* ==================== DATA STRUCTURES ==================== */

typedef struct {
    char name[256];
    char version[128];
    int line_num;      /* Source line number for debugging */
    bool is_dev;       /* Development dependency flag */
    bool is_optional;  /* Optional dependency flag */
} dep_entry_t;

typedef struct {
    dep_type_t type;
    dep_entry_t *entries;
    size_t count;
    size_t capacity;
} dep_graph_t;

/* Vulnerability database entry (simplified) */
typedef struct {
    char pkg[256];
    char version[128];  /* Minimum vulnerable version */
    sev_t severity;
    const char *cve_id;
    const char *description;
} vuln_entry_t;

/* Analysis result for a single dependency */
typedef struct {
    dep_entry_t entry;
    bool is_vulnerable;
    int vuln_count;
    sev_t max_severity;
    double resolution_score;  /* 0.0 - 1.0, higher is better */
} analysis_result_t;

/* ==================== GLOBAL STATE ==================== */

static dep_graph_t g_current = { DEP_COMPOUND, NULL, 0, 64 };
static vuln_entry_t g_vuln_db[MAX_VULN_DB_SIZE];
static size_t g_vuln_count = 0;
static analysis_result_t *g_results = NULL;

/* ==================== UTILITY FUNCTIONS ==================== */

static inline bool is_empty_or_whitespace(const char *s) {
    if (!s || !*s) return true;
    while (*s && isspace((unsigned char)*s)) s++;
    return !*s;
}

static inline void trim_left(char *s) {
    while (is_empty_or_whitespace(s)) s++;
}

static inline void trim_right(char *s, size_t len) {
    while (len > 0 && is_empty_or_whitespace(&s[len - 1])) len--;
    s[len] = '\0';
}

static inline char* trim(char *s) {
    trim_left(s);
    if (!*s) return s;
    size_t len = strlen(s);
    trim_right(s, len);
    return s;
}

/* ==================== FILE I/O HELPERS ==================== */

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int read_file_lines(const char *path, dep_entry_t **out_entries, 
                          size_t *out_count, size_t max_cap) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "Error: Failed to open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    dep_entry_t entries[max_cap];
    size_t count = 0;
    
    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), f) && count < max_cap) {
        trim(line);
        
        /* Skip empty lines and comments */
        if (is_empty_or_whitespace(line)) continue;
        if (line[0] == '#' || line[0] == ';' || line[0] == '//') continue;

        /* Parse based on file type - default: name@version format */
        char *at_pos = strchr(line, '@');
        if (!at_pos) {
            at_pos = strchr(line, ':');  /* Alternative separator */
        }
        
        dep_entry_t *e = &entries[count];
        e->line_num = count + 1;
        e->is_dev = false;
        e->is_optional = false;

        if (at_pos) {
            strncpy(e->name, line, at_pos - line);
            e->name[at_pos - line] = '\0';
            
            char *ver_start = trim(at_pos + 1);
            /* Handle ranges like ^1.2.3 or ~1.2.3 */
            while (*ver_start && (*ver_start == '^' || *ver_start == '~')) {
                ver_start++;
            }
            strncpy(e->version, ver_start, sizeof(e->version) - 1);
        } else {
            /* No separator found - assume name only */
            strncpy(e->name, line, sizeof(e->name) - 1);
            e->version[0] = '\0';
        }

        count++;
    }

    fclose(f);
    
    if (out_entries) *out_entries = entries;
    if (out_count) *out_count = count;
    return (int)count;
}

/* ==================== PARSER: NPM/Node.js ==================== */

static dep_type_t parse_npm(const char *path, dep_entry_t **entries_out, 
                           size_t *count_out) {
    dep_type_t type = DEP_NPM;
    
    /* Check if it's package.json or a lock file */
    FILE *f = fopen(path, "r");
    if (!f) return DEP_COMPOUND;

    char line[MAX_LINE_LEN];
    bool in_deps = false;
    dep_entry_t entries[8192];
    size_t count = 0;

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        
        /* Detect section */
        if (strstr(line, "\"dependencies\"") || strstr(line, "\"devDependencies\"")) {
            in_deps = true;
            continue;
        }
        if (in_deps && (line[0] == '}' || line[0] == ']')) {
            break;
        }

        /* Parse dependency entries */
        char *colon = strchr(line, ':');
        if (!colon) continue;

        dep_entry_t *e = &entries[count];
        e->line_num = 0;
        e->is_dev = false;
        e->is_optional = false;

        /* Determine if dev dependency */
        if (strstr(line, "\"devDependencies\"")) {
            e->is_dev = true;
        } else if (strstr(line, "\"optionalDependencies\"")) {
            e->is_optional = true;
        }

        char *name_end = strchr(colon + 1, ',');
        if (!name_end) name_end = strchr(colon + 1, '}');
        
        if (name_end) {
            size_t len = name_end - colon - 1;
            trim(&line[colon - line]);
            strncpy(e->name, &line[colon - line], len);
            e->name[len] = '\0';

            /* Extract version from the end of the line */
            char *ver_start = name_end + 1;
            while (*ver_start && isspace((unsigned char)*ver_start)) ver_start++;
            
            if (*ver_start == '"' || *ver_start == '\'') {
                size_t quote_len = 1;
                char q = *ver_start;
                ver_start++;
                for (size_t i = 0; i < sizeof(e->version) - 2 && 
                     ver_start[i] != '\n' && ver_start[i] != '"' && ver_start[i] != '\''; i++) {
                    if (ver_start[i] == q) break;
                    e->version[i] = ver_start[i];
                }
            } else {
                strncpy(e->version, ver_start, sizeof(e->version) - 1);
            }

            /* Clean up version string */
            trim_right(e->version, strlen(e->version));
            
            count++;
        }
    }

    fclose(f);
    
    if (entries_out) *entries_out = entries;
    if (count_out) *count_out = count;
    return type;
}

/* ==================== PARSER: Python/PyPI ==================== */

static dep_type_t parse_python(const char *path, dep_entry_t **entries_out, 
                              size_t *count_out) {
    dep_type_t type = DEP_PIP;
    
    FILE *f = fopen(path, "r");
    if (!f) return DEP_COMPOUND;

    dep_entry_t entries[8192];
    size_t count = 0;
    bool in_requirements = true;

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        
        /* Skip empty lines and comments */
        if (is_empty_or_whitespace(line) || line[0] == '#') continue;

        dep_entry_t *e = &entries[count];
        e->line_num = count + 1;
        e->is_dev = false;
        e->is_optional = false;

        /* Parse: package==version, package>=version, etc. */
        char *eq_pos = strchr(line, '=');
        if (eq_pos) {
            size_t name_len = eq_pos - line;
            strncpy(e->name, line, name_len);
            e->name[name_len] = '\0';

            /* Extract version specifier */
            char *ver_start = trim(eq_pos + 1);
            
            /* Handle extras like [dev,test] */
            if (*ver_start == '[') {
                ver_start++;
                while (*ver_start && *ver_start != ']') ver_start++;
                ver_start++;
            }

            strncpy(e->version, ver_start, sizeof(e->version) - 1);
            trim_right(e->version, strlen(e->version));
            
            count++;
        } else {
            /* Package without version */
            strncpy(e->name, line, sizeof(e->name) - 1);
            e->version[0] = '\0';
            count++;
        }
    }

    fclose(f);
    
    if (entries_out) *entries_out = entries;
    if (count_out) *count_out = count;
    return type;
}

/* ==================== PARSER: Go Modules ==================== */

static dep_type_t parse_go(const char *path, dep_entry_t **entries_out, 
                          size_t *count_out) {
    dep_type_t type = DEP_GOPATH;
    
    FILE *f = fopen(path, "r");
    if (!f) return DEP_COMPOUND;

    dep_entry_t entries[8192];
    size_t count = 0;

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        
        /* Skip empty lines and comments */
        if (is_empty_or_whitespace(line) || line[0] == '#') continue;

        dep_entry_t *e = &entries[count];
        e->line_num = count + 1;
        e->is_dev = false;
        e->is_optional = false;

        /* Parse: module name v1.2.3 */
        char *space_pos = strchr(line, ' ');
        if (space_pos) {
            size_t name_len = space_pos - line;
            strncpy(e->name, line, name_len);
            e->name[name_len] = '\0';

            /* Extract version */
            char *ver_start = trim(space_pos + 1);
            
            /* Handle indirect dependencies (go.mod v2.0+) */
            if (*ver_start == '(') {
                ver_start++;
                while (*ver_start && *ver_start != ')') ver_start++;
                ver_start++;
            }

            strncpy(e->version, ver_start, sizeof(e->version) - 1);
            trim_right(e->version, strlen(e->version));
            
            count++;
        } else {
            /* Module declaration line */
            if (strncmp(line, "module ", 7) == 0) {
                continue;  /* Skip module declaration */
            }
            strncpy(e->name, line, sizeof(e->name) - 1);
            e->version[0] = '\0';
            count++;
        }
    }

    fclose(f);
    
    if (entries_out) *entries_out = entries;
    if (count_out) *count_out = count;
    return type;
}

/* ==================== PARSER: Maven/Java ==================== */

static dep_type_t parse_maven(const char *path, dep_entry_t **entries_out, 
                             size_t *count_out) {
    dep_type_t type = DEP_MAVEN;
    
    FILE *f = fopen(path, "r");
    if (!f) return DEP_COMPOUND;

    dep_entry_t entries[8192];
    size_t count = 0;
    bool in_dependency = false;
    char current_name[256] = {0};
    char current_version[128] = {0};

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        
        /* Detect dependency section */
        if (strstr(line, "<dependencies>") || strstr(line, "</dependencies>")) {
            in_dependency = !strcmp(line, "</dependencies>");
            continue;
        }

        if (!in_dependency) continue;

        /* Parse groupId:artifactId:version format */
        char *colon1 = strchr(line, ':');
        if (colon1) {
            size_t name_len = colon1 - line;
            strncpy(current_name, line, name_len);
            current_name[name_len] = '\0';

            /* Find version tag */
            char *ver_start = strstr(line, "<version>");
            if (ver_start) {
                ver_start += 8;  /* Skip "<version>" */
                while (*ver_start && !is_empty_or_whitespace(ver_start)) ver_start++;
                
                size_t ver_len = 0;
                while (ver_start[ver_len] && 
                       !is_empty_or_whitespace(&ver_start[ver_len]) &&
                       ver_len < sizeof(current_version) - 1) {
                    current_version[ver_len++] = ver_start[ver_len];
                }
                current_version[ver_len] = '\0';

                /* Create entry */
                dep_entry_t *e = &entries[count];
                e->line_num = count + 1;
                e->is_dev = false;
                e->is_optional = false;
                
                strncpy(e->name, current_name, sizeof(e->name) - 1);
                strncpy(e->version, current_version, sizeof(e->version) - 1);
                
                count++;
            }
        }
    }

    fclose(f);
    
    if (entries_out) *entries_out = entries;
    if (count_out) *count_out = count;
    return type;
}

/* ==================== PARSER: Ruby/Gemfile ==================== */

static dep_type_t parse_ruby(const char *path, dep_entry_t **entries_out, 
                            size_t *count_out) {
    dep_type_t type = DEP_RUBY;
    
    FILE *f = fopen(path, "r");
    if (!f) return DEP_COMPOUND;

    dep_entry_t entries[8192];
    size_t count = 0;

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        
        /* Skip empty lines and comments */
        if (is_empty_or_whitespace(line) || line[0] == '#') continue;

        dep_entry_t *e = &entries[count];
        e->line_num = count + 1;
        e->is_dev = false;
        e->is_optional = false;

        /* Parse: gem 'name', '~> 1.2' or gem 'name', '>= 1.0' */
        char *quote_start = strchr(line, '\'');
        if (!quote_start) quote_start = strchr(line, '"');
        
        if (quote_start) {
            size_t name_len = quote_start - line;
            strncpy(e->name, line, name_len);
            e->name[name_len] = '\0';

            /* Extract version from after the closing quote */
            char *ver_start =