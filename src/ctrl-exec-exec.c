/*
 * ctrl-exec-exec - the privileged executor for ctrl-exec-agent.
 *
 * This is the small, root, no-network half of the privilege-separated agent.
 * The unprivileged front-end (ctrl-exec-agent, Perl) does the network, mTLS,
 * allowlist, schema and auth-hook work, then hands a validated request to this
 * binary over a local socket. This binary re-derives the script path and its
 * security profile from its OWN root-owned config (it never trusts the path or
 * profile in the message), then runs the script under that profile (mount
 * namespace with the control/audit dirs read-only, capability set, run_as,
 * no_new_privileges).
 *
 * THIS FILE, PHASE 2a: the config parser and `resolve` subcommand only. The
 * `resolve` mode is what the shared conformance test exercises - it must produce
 * exactly the security decision the Perl front-end (Exec::Agent::Config) makes
 * for the same files, or the executor would apply a different privilege than the
 * front-end believes. The socket server and the privileged exec path land in
 * phase 2b and reuse this parser.
 *
 * Deliberately dependency-light and bounded: fixed caps on counts/lengths,
 * full-line comments only (matching the Perl parser), no inline-# stripping.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <limits.h>

#define MAX_PROFILES   64
#define MAX_CAPS       32
#define MAX_WRITABLE   32
#define MAX_DIRS       32
#define NAMELEN       128
#define VALLEN       4096

typedef struct {
    char name[NAMELEN];
    char run_as[NAMELEN];          /* empty = unset (keep front-end user) */
    int  nnp;                      /* no_new_privileges; default 1 */
    char caps[MAX_CAPS][NAMELEN];
    int  ncaps;
    char writable[MAX_WRITABLE][VALLEN];
    int  nwritable;
} profile_t;

typedef struct {
    profile_t profiles[MAX_PROFILES];
    int       nprofiles;
    char      script_dirs[MAX_DIRS][VALLEN];
    int       ndirs;
} config_t;

/* ---- small helpers ---------------------------------------------------- */

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

/* Split src on any char in `seps`, preserving order, into dst[][len].
 * Empty fields are dropped (matches Perl `grep { length } split`). */
static int split_into(const char *src, const char *seps,
                      char *dst, size_t stride, int maxn, int *count) {
    *count = 0;
    const char *p = src;
    while (*p) {
        while (*p && strchr(seps, *p)) p++;       /* skip separators */
        if (!*p) break;
        if (*count >= maxn) return -1;
        char *out = dst + (size_t)(*count) * stride;
        size_t n = 0;
        while (*p && !strchr(seps, *p) && n + 1 < stride) out[n++] = *p++;
        out[n] = '\0';
        while (*p && !strchr(seps, *p)) p++;       /* overflow guard: consume rest */
        (*count)++;
    }
    return 0;
}

static profile_t *find_profile(config_t *c, const char *name) {
    for (int i = 0; i < c->nprofiles; i++)
        if (strcmp(c->profiles[i].name, name) == 0) return &c->profiles[i];
    return NULL;
}

static profile_t *intern_profile(config_t *c, const char *name) {
    profile_t *p = find_profile(c, name);
    if (p) return p;
    if (c->nprofiles >= MAX_PROFILES) return NULL;
    p = &c->profiles[c->nprofiles++];
    memset(p, 0, sizeof(*p));
    snprintf(p->name, sizeof(p->name), "%s", name);
    p->nnp = 1;                                    /* default on */
    return p;
}

/* ---- agent.conf parsing ----------------------------------------------- */
/* Returns 0 on success, -1 on a fatal config error (message on stderr). */

static int set_profile_field(profile_t *p, const char *k, const char *v,
                             const char *path) {
    if (strcmp(k, "run_as") == 0) {
        if (*v) {
            /* [A-Za-z_][A-Za-z0-9_-]* or all-digits */
            int ok = 1, alldig = 1;
            for (const char *q = v; *q; q++) if (!isdigit((unsigned char)*q)) alldig = 0;
            if (!alldig) {
                if (!(isalpha((unsigned char)v[0]) || v[0] == '_')) ok = 0;
                for (const char *q = v + 1; ok && *q; q++)
                    if (!(isalnum((unsigned char)*q) || *q == '_' || *q == '-')) ok = 0;
            }
            if (!ok) {
                fprintf(stderr, "Profile '%s': invalid run_as '%s' in '%s'\n",
                        p->name, v, path);
                return -1;
            }
            snprintf(p->run_as, sizeof(p->run_as), "%s", v);
        }
    } else if (strcmp(k, "caps") == 0) {
        if (split_into(v, ", \t", (char *)p->caps, sizeof(p->caps[0]), MAX_CAPS, &p->ncaps) != 0) {
            fprintf(stderr, "Profile '%s': too many caps in '%s'\n", p->name, path);
            return -1;
        }
        for (int i = 0; i < p->ncaps; i++) {
            const char *c = p->caps[i];
            int ok = (strncmp(c, "CAP_", 4) == 0) && c[4];
            for (const char *q = c + 4; ok && *q; q++)
                if (!(isupper((unsigned char)*q) || isdigit((unsigned char)*q) || *q == '_')) ok = 0;
            if (!ok) {
                fprintf(stderr, "Profile '%s': invalid capability '%s' (expected CAP_*) in '%s'\n",
                        p->name, c, path);
                return -1;
            }
        }
    } else if (strcmp(k, "writable") == 0) {
        if (split_into(v, ":", (char *)p->writable, sizeof(p->writable[0]), MAX_WRITABLE, &p->nwritable) != 0) {
            fprintf(stderr, "Profile '%s': too many writable paths in '%s'\n", p->name, path);
            return -1;
        }
        for (int i = 0; i < p->nwritable; i++)
            if (p->writable[i][0] != '/') {
                fprintf(stderr, "Profile '%s': writable path must be absolute: '%s' in '%s'\n",
                        p->name, p->writable[i], path);
                return -1;
            }
    } else if (strcmp(k, "no_new_privileges") == 0) {
        p->nnp = (strcasecmp(v, "1") == 0 || strcasecmp(v, "y") == 0 ||
                  strcasecmp(v, "yes") == 0 || strcasecmp(v, "true") == 0 ||
                  strcasecmp(v, "on") == 0) ? 1 : 0;
    }
    /* unknown profile keys are ignored, as in the Perl parser */
    return 0;
}

static int parse_agent_conf(const char *path, config_t *c) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "Cannot open config '%s'\n", path); return -1; }

    memset(c, 0, sizeof(*c));
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int section_profile = 0;
    profile_t *cur = NULL;
    int rc = 0;

    while ((len = getline(&line, &cap, f)) != -1) {
        if (len && line[len - 1] == '\n') line[len - 1] = '\0';
        char *s = trim(line);
        if (!*s || *s == '#') continue;            /* blank / full-line comment */

        if (*s == '[') {                           /* section header */
            char *e = strchr(s, ']');
            if (!e) { fprintf(stderr, "Malformed config line in '%s': %s\n", path, s); rc = -1; break; }
            *e = '\0';
            char *inner = trim(s + 1);
            char *sp = inner;
            while (*sp && !isspace((unsigned char)*sp)) sp++;
            char *sub = NULL;
            if (*sp) { *sp = '\0'; sub = trim(sp + 1); }
            if (strcmp(inner, "profile") == 0) {
                if (!sub || !*sub) {
                    fprintf(stderr, "Profile section needs a name ([profile <name>]) in '%s'\n", path);
                    rc = -1; break;
                }
                section_profile = 1;
                cur = intern_profile(c, sub);
                if (!cur) { fprintf(stderr, "Too many profiles in '%s'\n", path); rc = -1; break; }
            } else {
                section_profile = 0;
                cur = NULL;
            }
            continue;
        }

        char *eq = strchr(s, '=');
        if (!eq) continue;                          /* tolerate; Perl croaks, but
                                                       resolve only needs profiles */
        *eq = '\0';
        char *k = trim(s);
        char *v = trim(eq + 1);

        if (section_profile && cur) {
            if (set_profile_field(cur, k, v, path) != 0) { rc = -1; break; }
        } else if (strcmp(k, "script_dirs") == 0) {
            if (split_into(v, ":", (char *)c->script_dirs, sizeof(c->script_dirs[0]), MAX_DIRS, &c->ndirs) != 0) {
                fprintf(stderr, "Too many script_dirs in '%s'\n", path); rc = -1; break;
            }
        }
    }
    free(line);
    fclose(f);
    return rc;
}

/* ---- scripts.conf lookup ---------------------------------------------- */
/* Find one script by name. Returns 1 found (out_path/out_profile set),
 * 0 not present / skipped (matches a Perl-skipped entry: not allowlisted). */

static int find_script(const char *path, const char *want,
                       char *out_path, size_t plen,
                       char *out_profile, size_t prlen) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char *line = NULL; size_t cap = 0; ssize_t len; int found = 0;

    while ((len = getline(&line, &cap, f)) != -1) {
        if (len && line[len - 1] == '\n') line[len - 1] = '\0';
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *name = trim(s);
        if (strcmp(name, want) != 0) continue;

        /* Value: one bare path token + optional key=value annotations,
         * order-independent. Mirrors load_allowlist. */
        char *rest = trim(eq + 1);
        char scriptpath[VALLEN] = "", profile[NAMELEN] = "default";
        int havepath = 0, twopaths = 0;
        char *save = NULL, *tok = strtok_r(rest, " \t", &save);
        for (; tok; tok = strtok_r(NULL, " \t", &save)) {
            char *te = strchr(tok, '=');
            if (te && te != tok) {           /* annotation key=value */
                int isannot = 1;
                for (char *q = tok; q < te; q++)
                    if (!(islower((unsigned char)*q) || *q == '_')) isannot = 0;
                if (isannot) {
                    *te = '\0';
                    if (strcmp(tok, "profile") == 0)
                        snprintf(profile, sizeof(profile), "%s", te + 1);
                    continue;
                }
            }
            if (havepath) twopaths = 1;
            else { snprintf(scriptpath, sizeof(scriptpath), "%s", tok); havepath = 1; }
        }
        if (!havepath || twopaths) break;            /* skipped -> not allowlisted */
        if (scriptpath[0] != '/') break;             /* relative -> skipped */
        snprintf(out_path, plen, "%s", scriptpath);
        snprintf(out_profile, prlen, "%s", profile);
        found = 1;
        break;
    }
    free(line);
    fclose(f);
    return found;
}

/* realpath-or-literal, matching Perl `abs_path($p) // $p`. */
static void canon(const char *in, char *out, size_t n) {
    char buf[PATH_MAX];
    if (realpath(in, buf)) snprintf(out, n, "%s", buf);
    else                   snprintf(out, n, "%s", in);
}

static int path_in_dirs(const char *path, config_t *c) {
    if (c->ndirs == 0) return 1;                     /* no restriction */
    char rp[PATH_MAX]; canon(path, rp, sizeof(rp));
    for (int i = 0; i < c->ndirs; i++) {
        char rd[PATH_MAX]; canon(c->script_dirs[i], rd, sizeof(rd));
        size_t L = strlen(rd);
        while (L > 1 && rd[L - 1] == '/') rd[--L] = '\0';
        if (strcmp(rp, rd) == 0) return 1;
        if (strncmp(rp, rd, L) == 0 && rp[L] == '/') return 1;
    }
    return 0;
}

/* ---- resolve: print the canonical security decision -------------------- */

static int cmd_resolve(const char *agent_conf, const char *scripts_conf,
                       const char *name) {
    config_t *c = calloc(1, sizeof(*c));   /* ~8MB: heap, not stack */
    if (!c) { fprintf(stderr, "out of memory\n"); return 2; }
    if (parse_agent_conf(agent_conf, c) != 0) { free(c); return 2; }

    char spath[VALLEN], pname[NAMELEN];
    if (!find_script(scripts_conf, name, spath, sizeof(spath), pname, sizeof(pname))) {
        printf("DENY not-allowlisted\n");
        free(c); return 0;
    }
    if (!path_in_dirs(spath, c)) {
        printf("DENY not-in-script-dirs\n");
        free(c); return 0;
    }

    /* Resolve the profile. 'default' is built in (no run_as, no caps, no
     * writable, nnp=1) unless agent.conf overrides [profile default]. Any other
     * name must be defined, else fail-closed. */
    profile_t *p = find_profile(c, pname);
    profile_t builtin;
    if (!p) {
        if (strcmp(pname, "default") != 0) {
            printf("DENY undefined-profile\n"); free(c); return 0;
        }
        memset(&builtin, 0, sizeof(builtin));
        snprintf(builtin.name, sizeof(builtin.name), "default");
        builtin.nnp = 1;
        p = &builtin;
    }

    char caps[VALLEN] = "", writ[VALLEN] = "";
    for (int i = 0; i < p->ncaps; i++) {
        if (i) strncat(caps, ",", sizeof(caps) - strlen(caps) - 1);
        strncat(caps, p->caps[i], sizeof(caps) - strlen(caps) - 1);
    }
    for (int i = 0; i < p->nwritable; i++) {
        if (i) strncat(writ, ":", sizeof(writ) - strlen(writ) - 1);
        strncat(writ, p->writable[i], sizeof(writ) - strlen(writ) - 1);
    }

    printf("OK path=%s|profile=%s|run_as=%s|nnp=%d|caps=%s|writable=%s\n",
           spath, pname, p->run_as, p->nnp, caps, writ);
    free(c);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "resolve") == 0)
        return cmd_resolve(argv[2], argv[3], argv[4]);

    fprintf(stderr,
        "ctrl-exec-exec - privileged executor for ctrl-exec-agent\n"
        "usage: ctrl-exec-exec resolve <agent.conf> <scripts.conf> <script-name>\n"
        "       (serve mode - the socket server and privileged exec - lands in phase 2b)\n");
    return 1;
}
