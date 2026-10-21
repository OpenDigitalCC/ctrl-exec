/*
 * ctrl-exec-executor - the privileged executor for ctrl-exec-agent.
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
 * THIS FILE contains the config parser plus three subcommands: `resolve` (the
 * security decision, exercised by the shared conformance test), the socket
 * server (`serve`), and `check-path` (the script ownership rule, T-045); and
 * the privileged exec path that runs under a profile, including the delivery
 * of confidential run input (T-013: stdin, or a per-run directory of files
 * made by root and handed to the profile's run_as user).
 * The `resolve` mode must produce exactly the security decision the Perl
 * front-end (Exec::Agent::Config) makes for the same files, or the executor
 * would apply a different privilege than the front-end believes; the socket
 * server and the exec path reuse the same parser so they agree by construction.
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
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <sys/syscall.h>

/* mount_setattr(2) bits for a recursive read-only remount (kernel 5.12+).
 * Defined locally and called via syscall() so the binary depends on neither
 * <linux/mount.h> nor a newer glibc symbol (keeping the libc floor low, as with
 * the manual strtol). */
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
struct ce_mount_attr {
    uint64_t attr_set;
    uint64_t attr_clr;
    uint64_t propagation;
    uint64_t userns_fd;
};

/* Directories the executed action must never be able to modify: the agent's
 * control plane (config, allowlist, hook, certs, trusted map) and its state.
 * The privileged child bind-mounts each read-only inside its own mount
 * namespace, so even a root-profile action cannot tamper with the controls. */
static const char *const CONTROL_DIRS[] = {
    "/etc/ctrl-exec-agent",
    "/var/lib/ctrl-exec-agent",
};
#define N_CONTROL_DIRS ((int)(sizeof(CONTROL_DIRS) / sizeof(CONTROL_DIRS[0])))

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
    int       dirs_restrict;       /* script_dirs set non-empty, even if it
                                      yields no directories: deny all */
    int       ownership_strict;    /* script_ownership = strict (T-054);
                                      0 = warn, the default */
} config_t;

/* ---- small helpers ---------------------------------------------------- */

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

/* Pasted non-ASCII spaces (T-059): U+00A0, U+2000-U+200A (U+2007 among them)
 * and U+202F, UTF-8 encoded, each become one ASCII space, in place, before a
 * scripts.conf or agent.conf line is parsed. A line copied from a terminal or
 * chat UI then reads as typed. Mirrors Exec::Agent::Config::_ascii_spaces
 * (same sequences, same single-space replacement). Returns how many. */
static int ascii_spaces(char *s) {
    char *w = s;
    int n = 0;
    for (const char *r = s; *r; ) {
        const unsigned char *u = (const unsigned char *)r;
        if (u[0] == 0xC2 && u[1] == 0xA0) { *w++ = ' '; r += 2; n++; continue; }
        if (u[0] == 0xE2 && u[1] == 0x80 && ((u[2] >= 0x80 && u[2] <= 0x8A) || u[2] == 0xAF)) {
            *w++ = ' '; r += 3; n++; continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
    return n;
}

/* Split src on any char in `seps`, preserving order, into dst[][len].
 * Empty fields are dropped (matches Perl `grep { length } split`). Returns -1
 * when there are more than maxn fields or a field does not fit stride: a
 * truncated writable path or capability name would silently mean something
 * else, so it is a config error (the Perl parser enforces the same limits). */
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
        if (*p && !strchr(seps, *p)) return -1;    /* field too long */
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
    if (strlen(name) >= NAMELEN) return NULL;   /* never truncate a name */
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
            int ok = strlen(v) < sizeof(p->run_as), alldig = 1;
            for (const char *q = v; *q; q++) if (!isdigit((unsigned char)*q)) alldig = 0;
            if (!ok) {
                /* too long to hold: invalid, never truncated */
            } else if (!alldig) {
                if (!(isalpha((unsigned char)v[0]) || v[0] == '_')) ok = 0;
                for (const char *q = v + 1; ok && *q; q++)
                    if (!(isalnum((unsigned char)*q) || *q == '_' || *q == '-')) ok = 0;
            } else {
                /* All-digits uid/gid: bound it at load time so it cannot wrap
                 * to 0 (root) - or any unintended id - when the executor later
                 * truncates it to uid_t/gid_t at apply time. */
                unsigned long n = 0;
                for (const char *q = v; ok && *q; q++) {
                    if (n > (ULONG_MAX - 9) / 10) { ok = 0; break; }
                    n = n * 10 + (unsigned long)(*q - '0');
                }
                if (ok && (unsigned long)(uid_t)n != n) ok = 0;
            }
            if (!ok) {
                fprintf(stderr, "Profile '%s': invalid run_as '%s' in '%s'\n",
                        p->name, v, path);
                return -1;
            }
            snprintf(p->run_as, sizeof(p->run_as), "%s", v);
        }
    } else if (strcmp(k, "caps") == 0) {
        if (split_into(v, ", \t\r\n\v\f", (char *)p->caps, sizeof(p->caps[0]), MAX_CAPS, &p->ncaps) != 0) {
            fprintf(stderr, "Profile '%s': too many caps, or a name too long, in '%s'\n", p->name, path);
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
            fprintf(stderr, "Profile '%s': too many writable paths, or a path too long, in '%s'\n", p->name, path);
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

/* Character classes used by the Perl parser's regexes: \w is [A-Za-z0-9_]
 * (ASCII only: the Perl source has no unicode_strings feature, and this binary
 * never calls setlocale, so isalnum is the C locale's). */
static int is_word(int ch) { return isalnum((unsigned char)ch) || ch == '_'; }

/* Mirror of Perl's  /^\s*\[\s*(\w+)(?:\s+([\w.-]+))?\s*\]\s*$/  on a line
 * already trimmed and starting with '['. On success fills *sect and *sub (NULL
 * when absent) and returns 1; 0 means "not a header" (Perl then croaks). */
static int parse_header(char *s, char **sect, char **sub) {
    size_t n = strlen(s);
    if (n < 2 || s[n - 1] != ']') return 0;
    s[n - 1] = '\0';
    char *p = s + 1;
    while (isspace((unsigned char)*p)) p++;
    if (!is_word(*p)) return 0;
    *sect = p;
    while (is_word(*p)) p++;
    char *e = p;
    *sub = NULL;
    while (isspace((unsigned char)*p)) p++;
    if (*p) {
        if (p == e) return 0;                        /* \w+ then junk, no gap */
        char *b = p;
        while (is_word(*p) || *p == '.' || *p == '-') p++;
        if (p == b) return 0;
        char *se = p;
        while (isspace((unsigned char)*p)) p++;
        if (*p) return 0;
        *se = '\0';
        *sub = b;
    }
    *e = '\0';
    return 1;
}

/* Mirror of Perl's  /^\s*(\w+[\w-]*)\s*=\s*(.+?)\s*$/  on a raw (newline-
 * stripped) line. Fills *k and *v and returns 1, or 0 when the line does not
 * match. Quirk kept on purpose: a value of nothing but whitespace is the last
 * whitespace character (the regex's \s* backtracks one char to satisfy .+?),
 * while an empty value does not match at all. */
static int parse_kv(char *l, char **k, char **v) {
    while (isspace((unsigned char)*l)) l++;
    if (!is_word(*l)) return 0;
    char *kb = l;
    while (is_word(*l) || *l == '-') l++;
    char *ke = l;
    while (isspace((unsigned char)*l)) l++;
    if (*l != '=') return 0;
    char *rest = l + 1;
    if (!*rest) return 0;                            /* empty value: no match */
    *ke = '\0';
    *k = kb;
    char *r = rest;
    while (isspace((unsigned char)*r)) r++;
    if (!*r) { *v = rest + strlen(rest) - 1; return 1; }
    *v = trim(rest);
    return 1;
}

static int parse_agent_conf(const char *path, config_t *c) {
    FILE *f = fopen(path, "re");
    if (!f) { fprintf(stderr, "Cannot open config '%s'\n", path); return -1; }

    memset(c, 0, sizeof(*c));
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int section_profile = 0;
    int toplevel = 1;          /* before the first [section] header */
    profile_t *cur = NULL;
    int rc = 0;
    /* script_ownership: the last value wins and is validated after the loop,
     * as the Perl parser keeps the last value and validates it at the end. */
    char own[NAMELEN] = "warn";
    int own_long = 0;

    while ((len = getline(&line, &cap, f)) != -1) {
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        if ((size_t)len != strlen(line)) {          /* NUL byte: Perl rejects too */
            fprintf(stderr, "Malformed config line in '%s': contains a NUL byte\n", path);
            rc = -1; break;
        }
        ascii_spaces(line);
        char *s = line;
        while (isspace((unsigned char)*s)) s++;
        if (!*s || *s == '#') continue;            /* blank / full-line comment */

        if (*s == '[') {                           /* section header */
            char *sect = NULL, *sub = NULL;
            if (!parse_header(trim(s), &sect, &sub)) {
                fprintf(stderr, "Malformed config line in '%s': %s\n", path, line);
                rc = -1; break;
            }
            toplevel = 0;
            if (strcasecmp(sect, "profile") == 0) {
                if (!sub || !*sub) {
                    fprintf(stderr, "Profile section needs a name ([profile <name>]) in '%s'\n", path);
                    rc = -1; break;
                }
                section_profile = 1;
                cur = intern_profile(c, sub);
                if (!cur) {
                    fprintf(stderr, "Too many profiles, or a profile name too long, in '%s'\n", path);
                    rc = -1; break;
                }
            } else {
                section_profile = 0;
                cur = NULL;
            }
            continue;
        }

        char *k, *v;
        if (!parse_kv(line, &k, &v)) {
            fprintf(stderr, "Malformed config line in '%s': %s\n", path, line);
            rc = -1; break;
        }

        if (section_profile && cur) {
            if (set_profile_field(cur, k, v, path) != 0) { rc = -1; break; }
        } else if (toplevel) {
            if (strcmp(k, "profiles") == 0 || strcmp(k, "tags") == 0) {
                /* names the Perl parser keeps its own tables under */
                fprintf(stderr, "Reserved config key '%s' in '%s'\n", k, path);
                rc = -1; break;
            }
            if (strcmp(k, "script_dirs") == 0) {
                c->dirs_restrict = 1;                /* any value restricts, even ":" */
                if (split_into(v, ":", (char *)c->script_dirs, sizeof(c->script_dirs[0]), MAX_DIRS, &c->ndirs) != 0) {
                    fprintf(stderr, "Too many script_dirs, or one too long, in '%s'\n", path); rc = -1; break;
                }
            } else if (strcmp(k, "script_ownership") == 0) {
                own_long = strlen(v) >= sizeof(own);
                snprintf(own, sizeof(own), "%s", v);
            }
        }
        /* keys in any other section are ignored, as in the Perl parser */
    }
    free(line);
    fclose(f);
    if (rc == 0) {
        /* KEEP IN SYNC WITH Exec::Agent::Config::_validate_config: warn or
         * strict, anything else is a config error. */
        if (!own_long && strcmp(own, "strict") == 0) c->ownership_strict = 1;
        else if (own_long || strcmp(own, "warn") != 0) {
            fprintf(stderr, "Invalid script_ownership '%s%s' in '%s' (expected warn or strict)\n",
                    own, own_long ? "..." : "", path);
            rc = -1;
        }
    }
    return rc;
}

/* ---- confidential run input (T-013): names and modes -------------------- */
/* An input field name: [A-Za-z0-9_.-]{1,64}, and neither "." nor "..", exactly
 * as Exec::Input (the API and the agent). It doubles as a file name in the
 * per-run directory, so it can never hold '/' or name the directory itself. */
#define INPUT_NAME_MAX   64
#define INPUT_MODE_LEN   80              /* "raw:" + a 64-char name + NUL fits */

static int input_name_ok(const char *s, size_t n) {
    if (n < 1 || n > INPUT_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (!(isalnum(ch) || ch == '_' || ch == '.' || ch == '-')) return 0;
    }
    if (n == 1 && s[0] == '.') return 0;
    if (n == 2 && s[0] == '.' && s[1] == '.') return 0;
    return 1;
}

/* A scripts.conf input= value: context, raw, raw:<name> or fields. Mirrors
 * Exec::Agent::Config::input_mode_problem; anything else skips the script. */
static int input_mode_ok(const char *v) {
    if (strcmp(v, "context") == 0 || strcmp(v, "raw") == 0 || strcmp(v, "fields") == 0)
        return 1;
    if (strncmp(v, "raw:", 4) == 0) return input_name_ok(v + 4, strlen(v + 4));
    return 0;
}

/* ---- confidential output (T-053) ---------------------------------------- */
/* A scripts.conf output= value: stored (the default) or confidential. Mirrors
 * Exec::Agent::Config::output_mode_problem; anything else skips the script.
 * The executor neither stores nor logs a run's output, so it uses the mode for
 * nothing else: the front end marks a confidential result for the dispatcher.
 * It is parsed here so that a script the front end skipped for a bad value is
 * skipped here too, and so `resolve` shows the same decision as the front end. */
#define OUTPUT_MODE_LEN  16

static int output_mode_ok(const char *v) {
    return strcmp(v, "stored") == 0 || strcmp(v, "confidential") == 0;
}

/* ---- dispatchers= (T-063) ------------------------------------------------ */
/* A dispatcher id: an ASCII letter or digit, then letters, digits, '.', '_' or
 * '-', at most 64 characters. Mirrors Exec::Agent::AgentPairing::
 * valid_dispatcher_id (this file never calls setlocale, so isalnum is the C
 * locale's). */
#define DISP_ID_MAX 64

static int disp_id_ok(const char *s, size_t n) {
    if (n < 1 || n > DISP_ID_MAX || !isalnum((unsigned char)s[0])) return 0;
    for (size_t i = 1; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (!(isalnum(ch) || ch == '.' || ch == '_' || ch == '-')) return 0;
    }
    return 1;
}

/* A scripts.conf dispatchers= value: one or more dispatcher ids separated by
 * single commas, shorter than VALLEN. Mirrors Exec::Agent::Config::
 * dispatchers_problem; anything else skips the script. */
static int dispatchers_ok(const char *v) {
    if (strlen(v) >= VALLEN) return 0;
    for (const char *p = v; ; ) {
        const char *c = strchr(p, ',');
        size_t n = c ? (size_t)(c - p) : strlen(p);
        if (!disp_id_ok(p, n)) return 0;
        if (!c) return 1;
        p = c + 1;
    }
}

/* Is `disp` one of the ids in a dispatchers= value that passed dispatchers_ok?
 * Exact, case-sensitive comparison, as in the Perl front end. */
static int dispatchers_has(const char *list, const char *disp) {
    size_t dl = strlen(disp);
    for (const char *p = list; ; ) {
        const char *c = strchr(p, ',');
        size_t n = c ? (size_t)(c - p) : strlen(p);
        if (n == dl && memcmp(p, disp, n) == 0) return 1;
        if (!c) return 0;
        p = c + 1;
    }
}

/* ---- scripts.conf lookup ---------------------------------------------- */
/* Find one script by name. Returns 1 found (out_path/out_profile/out_input/
 * out_disp set, and out_output when it is not NULL), 0 not present / skipped
 * (matches a Perl-skipped entry: not allowlisted). out_disp is the entry's
 * dispatchers= value, or "" when it has none (every dispatcher). Mirrors
 * load_allowlist: a skipped line never replaces an earlier valid one and a
 * later valid line replaces an earlier one (last valid entry wins). Within a
 * line the last profile=, input=, output= and dispatchers= win, as in the Perl
 * annotation hash. */

static int find_script(const char *path, const char *want,
                       char *out_path, size_t plen,
                       char *out_profile, size_t prlen,
                       char *out_input, size_t inlen,
                       char *out_output, size_t outlen,
                       char *out_disp, size_t dlen) {
    FILE *f = fopen(path, "re");
    if (!f) return 0;
    char *line = NULL; size_t cap = 0; ssize_t len; int found = 0;

    while ((len = getline(&line, &cap, f)) != -1) {
        if (len && line[len - 1] == '\n') line[--len] = '\0';
        if ((size_t)len != strlen(line)) continue;   /* NUL byte: skipped */
        ascii_spaces(line);
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) continue;
        *eq = '\0';
        char *name = trim(s);
        if (!*name) continue;
        int namewell = 1;                            /* [\w-]+ */
        for (char *q = name; *q; q++)
            if (!(is_word(*q) || *q == '-')) namewell = 0;
        if (!namewell) continue;
        if (strcmp(name, want) != 0) continue;

        /* Value: one bare path token + optional key=value annotations,
         * order-independent. Mirrors load_allowlist. */
        char *rest = trim(eq + 1);
        char scriptpath[VALLEN] = "", profile[NAMELEN] = "default";
        const char *profv = NULL, *inputv = NULL, *outputv = NULL,  /* last of each wins */
                   *dispv = NULL;
        int havepath = 0, twopaths = 0, toolong = 0;
        char *save = NULL, *tok = strtok_r(rest, " \t\r\n\v\f", &save);
        for (; tok; tok = strtok_r(NULL, " \t\r\n\v\f", &save)) {
            char *te = strchr(tok, '=');
            if (te && te != tok) {           /* annotation key=value */
                int isannot = 1;
                for (char *q = tok; q < te; q++)
                    if (!(islower((unsigned char)*q) || *q == '_')) isannot = 0;
                if (isannot) {
                    *te = '\0';
                    if (strcmp(tok, "profile") == 0)    profv  = te + 1;
                    else if (strcmp(tok, "input") == 0) inputv = te + 1;
                    else if (strcmp(tok, "output") == 0) outputv = te + 1;
                    /* dispatcher= is read as dispatchers= (T-063); across the two
                     * spellings the last on the line wins, as in the Perl parser. */
                    else if (strcmp(tok, "dispatchers") == 0 ||
                             strcmp(tok, "dispatcher") == 0) dispv = te + 1;
                    continue;
                }
            }
            if (havepath) twopaths = 1;
            else if (strlen(tok) >= sizeof(scriptpath)) { toolong = 1; havepath = 1; }
            else { snprintf(scriptpath, sizeof(scriptpath), "%s", tok); havepath = 1; }
        }
        if (profv) {
            if (strlen(profv) >= sizeof(profile)) toolong = 1;
            else snprintf(profile, sizeof(profile), "%s", profv);
        }
        if (!havepath || twopaths || toolong) continue;   /* skipped entry */
        /* A bad input= value skips the script, as in the Perl parser: never
         * deliver input in a form the operator did not write. */
        if (inputv && !input_mode_ok(inputv)) continue;
        /* Likewise a bad output= value (T-053): never run a script whose
         * confidentiality the front end could not establish. */
        if (outputv && !output_mode_ok(outputv)) continue;
        /* Likewise a bad dispatchers= value (T-063): a typo must never widen
         * the script to every dispatcher. */
        if (dispv && !dispatchers_ok(dispv)) continue;
        if (scriptpath[0] != '/') continue;               /* relative -> skipped */
        snprintf(out_path, plen, "%s", scriptpath);
        snprintf(out_profile, prlen, "%s", profile);
        snprintf(out_input, inlen, "%s", inputv ? inputv : "context");
        if (out_output) snprintf(out_output, outlen, "%s", outputv ? outputv : "stored");
        snprintf(out_disp, dlen, "%s", dispv ? dispv : "");   /* < VALLEN: fits */
        found = 1;                                        /* a later one may replace it */
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
    if (!c->dirs_restrict) return 1;                 /* no restriction */
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

/* ---- script ownership (T-045) ------------------------------------------ */
/* An allowlisted script, and every directory from / down to it, must be owned
 * by root and writable by neither group nor other, and the script must be a
 * regular file. Otherwise a user who can write any of them can change what this
 * root process runs. This holds whatever the profile's run_as: scripts.conf is
 * root's policy, so its scripts are root's files.
 *
 * The walk opens each component with openat(O_PATH|O_NOFOLLOW) relative to the
 * already-checked directory fd and checks it with fstat, so what is checked is
 * what was opened. A symbolic link is followed only after the directory holding
 * it has passed (so only root can have made or changed the link); its target is
 * walked by the same rule. More than MAX_SYMLINKS links is refused.
 *
 * Why the script is then exec'd by path (with a dev/ino re-check) rather than by
 * fd: see run_with_profile.
 *
 * The Perl front end applies the same rule (Exec::Agent::Config::
 * script_owner_check) to report a refusal early. KEEP IN SYNC: the same walk,
 * the same check order, the same reason texts (t/exec-ownership-parity.t). */

#define MAX_SYMLINKS 40
#define MAX_EXEMPT   64

typedef struct {
    int    have_extra;             /* test seam only: a uid trusted like root */
    uid_t  extra_uid;
    int    nexempt;                /* test seam only: unchecked ancestors */
    dev_t  ex_dev[MAX_EXEMPT];
    ino_t  ex_ino[MAX_EXEMPT];
} trust_t;

/* The production rule trusts root alone. A test build (cc -DCE_TEST_SEAM, never
 * the installed binary) may also trust CE_TEST_TRUSTED_UID and skip the checks
 * on the strict ancestors of CE_TEST_TRUSTED_TOP, because an unprivileged test
 * cannot create a root-owned directory chain. */
static void trust_init(trust_t *t) {
    memset(t, 0, sizeof(*t));
#ifdef CE_TEST_SEAM
    const char *u = getenv("CE_TEST_TRUSTED_UID");
    if (u && *u) {
        unsigned long v = 0;
        for (const char *q = u; *q >= '0' && *q <= '9'; q++) v = v * 10 + (unsigned long)(*q - '0');
        t->extra_uid = (uid_t)v; t->have_extra = 1;
    }
    const char *top = getenv("CE_TEST_TRUSTED_TOP");
    char rp[PATH_MAX];
    if (top && *top && realpath(top, rp)) {
        char *last = strrchr(rp, '/');
        for (char *p = rp; p && p <= last && t->nexempt < MAX_EXEMPT; p = strchr(p + 1, '/')) {
            char pre[PATH_MAX];
            size_t n = (p == rp) ? 1 : (size_t)(p - rp);
            memcpy(pre, rp, n); pre[n] = '\0';
            struct stat st;
            if (stat(pre, &st) != 0) break;
            t->ex_dev[t->nexempt] = st.st_dev; t->ex_ino[t->nexempt] = st.st_ino; t->nexempt++;
            if (p == last) break;
        }
    }
#endif
}

/* Writes the reason one node breaks the rule into why and returns 1, or 0 when
 * it passes. Order of checks: type, owner, world-writable, group-writable. */
static int node_problem(const trust_t *t, const char *shown, const struct stat *st,
                        int want_file, char *why, size_t wl) {
    if (want_file) {
        if (!S_ISREG(st->st_mode)) { snprintf(why, wl, "'%s' is not a regular file", shown); return 1; }
    } else {
        if (!S_ISDIR(st->st_mode)) { snprintf(why, wl, "'%s' is not a directory", shown); return 1; }
        for (int i = 0; i < t->nexempt; i++)
            if (t->ex_dev[i] == st->st_dev && t->ex_ino[i] == st->st_ino) return 0;
    }
    if (st->st_uid != 0 && !(t->have_extra && st->st_uid == t->extra_uid)) {
        snprintf(why, wl, "'%s' is owned by uid %lu, not root", shown, (unsigned long)st->st_uid);
        return 1;
    }
    if (st->st_mode & S_IWOTH) { snprintf(why, wl, "'%s' is world-writable", shown); return 1; }
    if (st->st_mode & S_IWGRP) { snprintf(why, wl, "'%s' is group-writable", shown); return 1; }
    return 0;
}

/* Walk `path` from / and apply the rule. Returns 0 when it passes (*final_st is
 * the script's stat), 1 when it is refused (why: the path and the rule), or -1
 * when it cannot be examined (why: the path and the error; e.g. it does not
 * exist, or the caller cannot search a directory on the way). */
static int script_trust_check(const char *path, char *why, size_t wl, struct stat *final_st) {
    trust_t t;
    trust_init(&t);
    if (path[0] != '/') { snprintf(why, wl, "'%s' is not an absolute path", path); return -1; }

    char rest[2 * PATH_MAX];               /* what is left to walk */
    char cur[PATH_MAX] = "/";              /* the checked directory, symlink-free */
    if (strlen(path) >= sizeof(rest)) { snprintf(why, wl, "'%.200s...' is too long", path); return -1; }
    snprintf(rest, sizeof(rest), "%s", path);

    struct stat st;
    int dfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0 || fstat(dfd, &st) != 0) {
        snprintf(why, wl, "'/': %s", strerror(errno));
        if (dfd >= 0) close(dfd);
        return -1;
    }
    if (node_problem(&t, "/", &st, 0, why, wl)) { close(dfd); return 1; }

    int links = 0, have_final = 0, rc = 0;
    size_t pos = 0;
    for (;;) {
        const char *r = rest + pos;
        while (*r == '/') r++;
        if (!*r) break;
        size_t n = 0;
        while (r[n] && r[n] != '/') n++;
        char comp[NAME_MAX + 1];
        if (n > NAME_MAX) { snprintf(why, wl, "a component of '%s' is too long", path); rc = -1; break; }
        memcpy(comp, r, n); comp[n] = '\0';
        r += n;
        const char *q = r;
        while (*q == '/') q++;
        int more = (*q != '\0');
        pos = (size_t)(r - rest);

        if (strcmp(comp, ".") == 0) continue;

        char next[PATH_MAX];
        int nfd;
        if (strcmp(comp, "..") == 0) {
            snprintf(next, sizeof(next), "%s", cur);
            char *s = strrchr(next, '/');
            if (s == next) next[1] = '\0'; else if (s) *s = '\0';
            nfd = openat(dfd, "..", O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        } else {
            int w = snprintf(next, sizeof(next), "%s%s%s", cur, strcmp(cur, "/") ? "/" : "", comp);
            if (w < 0 || (size_t)w >= sizeof(next)) { snprintf(why, wl, "'%s' is too long", path); rc = -1; break; }
            nfd = openat(dfd, comp, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        }
        if (nfd < 0 || fstat(nfd, &st) != 0) {
            snprintf(why, wl, "'%s': %s", next, strerror(errno));
            if (nfd >= 0) close(nfd);
            rc = -1; break;
        }

        if (S_ISLNK(st.st_mode)) {
            close(nfd);
            if (++links > MAX_SYMLINKS) {
                snprintf(why, wl, "'%s' has too many levels of symbolic links", next);
                rc = 1; break;
            }
            /* The link's directory (dfd) has passed: only root can change it. */
            char tgt[PATH_MAX];
            ssize_t tl = readlinkat(dfd, comp, tgt, sizeof(tgt) - 1);
            if (tl < 0) { snprintf(why, wl, "'%s': %s", next, strerror(errno)); rc = -1; break; }
            tgt[tl] = '\0';
            if (tgt[0] == '/') {
                close(dfd);
                dfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
                if (dfd < 0 || fstat(dfd, &st) != 0) {
                    snprintf(why, wl, "'/': %s", strerror(errno)); rc = -1; break;
                }
                snprintf(cur, sizeof(cur), "/");
                if (node_problem(&t, "/", &st, 0, why, wl)) { rc = 1; break; }
            }
            char nr[sizeof(rest)];
            int w = snprintf(nr, sizeof(nr), "%s/%s", tgt, rest + pos);
            if (w < 0 || (size_t)w >= sizeof(nr)) { snprintf(why, wl, "'%s' is too long", path); rc = -1; break; }
            memcpy(rest, nr, (size_t)w + 1);
            pos = 0;
            continue;
        }

        if (S_ISDIR(st.st_mode) || more) {
            /* A directory to descend into; a non-directory with more to come
             * is refused here as "not a directory". */
            if (node_problem(&t, next, &st, 0, why, wl)) { close(nfd); rc = 1; break; }
            close(dfd);
            dfd = nfd;
            snprintf(cur, sizeof(cur), "%s", next);
            continue;
        }
        close(nfd);
        if (node_problem(&t, next, &st, 1, why, wl)) { rc = 1; break; }
        *final_st = st;
        have_final = 1;
    }
    if (dfd >= 0) close(dfd);
    if (rc != 0) return rc;
    if (!have_final) {                       /* "/", "dir/", "dir/.", "dir/.." */
        snprintf(why, wl, "'%s' is not a regular file", cur);
        return 1;
    }
    return 0;
}

/* check-path: print the ownership verdict for one path (OK / DENY <reason> /
 * UNKNOWN <reason>). Exit 0 for OK, 1 otherwise. For operators and the parity
 * test; the serve path applies the same check before every run. */
static int cmd_check_path(const char *path) {
    char why[PATH_MAX + 256];
    struct stat st;
    int rc = script_trust_check(path, why, sizeof(why), &st);
    if (rc == 0) { printf("OK\n"); return 0; }
    printf("%s %s\n", rc == 1 ? "DENY" : "UNKNOWN", why);
    return 1;
}

/* ---- resolve: print the canonical security decision -------------------- */

static int cmd_resolve(const char *agent_conf, const char *scripts_conf,
                       const char *name) {
    config_t *c = calloc(1, sizeof(*c));   /* ~8MB: heap, not stack */
    if (!c) { fprintf(stderr, "out of memory\n"); return 2; }
    if (parse_agent_conf(agent_conf, c) != 0) { free(c); return 2; }

    char spath[VALLEN], pname[NAMELEN], imode[INPUT_MODE_LEN], omode[OUTPUT_MODE_LEN];
    char dlist[VALLEN];
    if (!find_script(scripts_conf, name, spath, sizeof(spath), pname, sizeof(pname),
                     imode, sizeof(imode), omode, sizeof(omode), dlist, sizeof(dlist))) {
        printf("DENY not-allowlisted\n");
        free(c); return 0;
    }
    if (!path_in_dirs(spath, c)) {
        printf("DENY not-in-script-dirs\n");
        free(c); return 0;
    }

    /* Resolve the profile. Every profile - including 'default' (the name an
     * unannotated script resolves to) - must be defined in agent.conf, else
     * fail-closed. There is NO built-in fallback: an undefined profile is denied
     * rather than run under an implicit context, so nothing ever runs as root by
     * omission. Operators ship a restrictive [profile default]. */
    profile_t *p = find_profile(c, pname);
    if (!p) {
        printf("DENY undefined-profile\n"); free(c); return 0;
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

    /* dispatchers=* : no limit, every trusted dispatcher (T-063). */
    printf("OK path=%s|profile=%s|run_as=%s|nnp=%d|caps=%s|writable=%s|input=%s|output=%s"
           "|ownership=%s|dispatchers=%s\n",
           spath, pname, p->run_as, p->nnp, caps, writ, imode, omode,
           c->ownership_strict ? "strict" : "warn", dlist[0] ? dlist : "*");
    free(c);
    return 0;
}

/* ====================================================================== *
 *  serve mode: socket + peer-cred + framed request -> profiled exec
 * ====================================================================== */

/* Wire framing. Request (front-end -> executor), all big-endian length-prefixed,
 * field = [u32 len][bytes]:
 *   v1: [u32 total] [field reqid] [field disp] [field script] [field stdin]
 *       [u32 argc] argc*[field arg]
 *   v2: [u32 total] [u32 FRAME_V2_MAGIC] [field reqid] [field disp] [field script]
 *       [field stdin] [field context] [u32 argc] argc*[field arg]
 *       [u32 nfields] nfields*([field name] [field value])     (T-013)
 * Response (executor -> front-end):
 *   [i32 exit] [u32 len][stdout] [u32 len][stderr]
 * Length-prefixed throughout so args/stdin may hold arbitrary bytes (args still
 * cannot contain NUL - execv requires C strings - but stdin may).
 *
 * disp is the dispatcher id the agent resolved from its trusted map for the
 * run's connection (issuing CA + certificate serial). Only scripts.conf
 * dispatchers= (T-063) reads it: the executor refuses a limited script when
 * disp is not in the list. It is the agent's attestation, not something this
 * process can check against a certificate.
 *
 * v2 carries confidential run input. In v2, stdin is the context JSON for an
 * input=context script (with an "input" object when there is input), context
 * is the context JSON for CTRL_EXEC_CONTEXT (no input, no caller token; the
 * agent builds both), and the fields are the input itself. The executor never
 * parses JSON: it takes the mode from its own scripts.conf and picks which of
 * these to deliver. FRAME_V2_MAGIC sits where v1 has the reqid length and is
 * larger than MAX_FRAME, so an executor that predates v2 fails its first length
 * check and replies "malformed request" without running anything; this
 * executor reads either form (a v1 frame is a run with no input). */

#define MAX_FRAME   (16 * 1024 * 1024)   /* 16MB request cap */
#define MAX_ARGS    256

/* Confidential run input (T-013). The agent enforces max_input_bytes (default
 * 1 MiB) and 32 fields before anything reaches here; these are the executor's
 * own bounds, checked on the frame before any of it is used. MAX_INPUT_BYTES
 * leaves headroom over the default, and a max_input_bytes above it is refused
 * here with a reason that names the limit. */
#define FRAME_V2_MAGIC   0xCE0E0002u
#define MAX_INPUT_FIELDS 32
#define MAX_INPUT_BYTES  (4 * 1024 * 1024)
#define RMTREE_MAX_DEPTH 16

static int read_all(int fd, void *buf, size_t n) {
    char *p = buf; size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r == 0) return -1;             /* short */
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)r;
    }
    return 0;
}
static int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf; size_t put = 0;
    while (put < n) {
        ssize_t w = write(fd, p + put, n - put);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        put += (size_t)w;
    }
    return 0;
}
static int read_u32(int fd, uint32_t *v) {
    unsigned char b[4];
    if (read_all(fd, b, 4) != 0) return -1;
    *v = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
    return 0;
}
static int write_u32(int fd, uint32_t v) {
    unsigned char b[4] = { v>>24, v>>16, v>>8, v };
    return write_all(fd, b, 4);
}

/* Read a length-prefixed field from an in-memory buffer (the already-read
 * frame), advancing *off. Returns malloc'd NUL-terminated string + sets *len. */
static char *take_field(const unsigned char *buf, uint32_t total, uint32_t *off, uint32_t *len) {
    if (*off + 4 > total) return NULL;
    uint32_t l = ((uint32_t)buf[*off]<<24)|((uint32_t)buf[*off+1]<<16)|
                 ((uint32_t)buf[*off+2]<<8)|buf[*off+3];
    *off += 4;
    if (l > total - *off) return NULL;
    char *s = malloc((size_t)l + 1);
    if (!s) return NULL;
    memcpy(s, buf + *off, l);
    s[l] = '\0';
    *off += l;
    if (len) *len = l;
    return s;
}

static uint32_t be32(const unsigned char *b) {
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
}

/* A field read in place: a pointer into the frame and its length, no copy.
 * Input values are used this way, so the only copies of them in this process
 * are the frame itself and what the kernel holds for the pipe or file. */
typedef struct { const unsigned char *p; uint32_t len; } view_t;

static int take_view(const unsigned char *buf, uint32_t total, uint32_t *off, view_t *v) {
    if (total - *off < 4) return -1;
    uint32_t l = be32(buf + *off);
    *off += 4;
    if (l > total - *off) return -1;
    v->p = buf + *off;
    v->len = l;
    *off += l;
    return 0;
}

/* Zero memory that held input before it is freed (volatile, so the stores are
 * not optimised away as dead). */
static void wipe(void *p, size_t n) {
    volatile unsigned char *q = p;
    while (n--) *q++ = 0;
}

/* Recursively make a subtree read-only via mount_setattr(2). Returns 0, or -1
 * with errno set (ENOSYS on a pre-5.12 kernel / arch without the syscall). */
static int mount_ro_recursive(const char *path) {
#ifdef SYS_mount_setattr
    struct ce_mount_attr a;
    memset(&a, 0, sizeof(a));
    a.attr_set = MOUNT_ATTR_RDONLY;
    return (int)syscall(SYS_mount_setattr, AT_FDCWD, path, AT_RECURSIVE, &a, sizeof(a));
#else
    (void)path; errno = ENOSYS; return -1;
#endif
}

/* ---- privileged child setup ------------------------------------------- */
/* The run_as user's identity for the action's environment: HOME, USER and
 * LOGNAME, taken from the agent host's own passwd entry for that user (as su -
 * and systemd User= do). Filled by apply_profile only when the profile has a
 * run_as with a passwd entry; otherwise `set` stays 0 and the action gets PATH
 * alone. Nothing here comes from the request. */
#define ENV_STR_MAX (PATH_MAX + 16)
typedef struct {
    int  set;
    char home[ENV_STR_MAX];
    char user[ENV_STR_MAX];
    char logname[ENV_STR_MAX];
} user_env_t;

/* Copy pw into ue. The passwd entry lives in libc static storage that later
 * lookups (initgroups) may overwrite, so copy it at once. Returns 0, or -1 if a
 * field does not fit: fail closed rather than hand the action a truncated HOME
 * that names a different directory. */
static int user_env_from(const struct passwd *pw, user_env_t *ue) {
    ue->set = 0;
    if (!pw || !pw->pw_dir || !pw->pw_name) return 0;
    int a = snprintf(ue->home,    sizeof(ue->home),    "HOME=%s",    pw->pw_dir);
    int b = snprintf(ue->user,    sizeof(ue->user),    "USER=%s",    pw->pw_name);
    int c = snprintf(ue->logname, sizeof(ue->logname), "LOGNAME=%s", pw->pw_name);
    if (a < 0 || b < 0 || c < 0 || (size_t)a >= sizeof(ue->home) ||
        (size_t)b >= sizeof(ue->user) || (size_t)c >= sizeof(ue->logname)) {
        fprintf(stderr, "executor: run_as passwd entry too long for the environment\n");
        return -1;
    }
    ue->set = 1;
    return 0;
}

/* Apply the profile in the forked child just before exec. Returns 0 or -1.
 * COMPILE-VERIFIED; the namespace/cap/setuid paths require root + CAP_SYS_ADMIN
 * and are exercised on a real host (see the on-host test plan). With
 * allow_unpriv and a non-root euid (test only), the privileged steps are
 * skipped and only no_new_privileges is applied. */
static int apply_profile(const profile_t *p, int allow_unpriv, user_env_t *ue) {
    int is_root = (geteuid() == 0);
    ue->set = 0;

    if (!is_root) {
        if (!allow_unpriv) { fprintf(stderr, "executor: must run as root\n"); return -1; }
        if (p->run_as[0] || p->ncaps > 0) {
            fprintf(stderr, "executor: profile needs privilege but euid != 0\n");
            return -1;
        }
        if (p->nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
        return 0;
    }

    /* Every capability the profile keeps must be one this executor holds:
     * cap_set_proc below cannot grant a capability that is not in the permitted
     * set, so say which one is missing instead of a bare EPERM. A container
     * that did not add the capability to its own set is the usual cause. */
    if (p->ncaps > 0) {
        cap_t cur = cap_get_proc();
        if (!cur) { perror("executor: cap_get_proc"); return -1; }
        for (int i = 0; i < p->ncaps; i++) {
            cap_value_t cv;
            cap_flag_value_t have = CAP_CLEAR;
            if (cap_from_name(p->caps[i], &cv) != 0 ||
                cap_get_flag(cur, cv, CAP_PERMITTED, &have) != 0 || have != CAP_SET) {
                fprintf(stderr, "executor: profile '%s' keeps %s, which the executor "
                                "does not hold (in a container, add it to the "
                                "container's capabilities: see DOCKER.md)\n",
                        p->name, p->caps[i]);
                cap_free(cur);
                return -1;
            }
        }
        cap_free(cur);
    }

    /* Control-plane integrity: control/state dirs read-only in this action's
     * mount namespace. CAP_SYS_ADMIN required - we have it as root on a host;
     * a container must be given it (and an AppArmor profile that allows mount),
     * or every run fails here, closed. */
    if (unshare(CLONE_NEWNS) != 0) {
        fprintf(stderr, "executor: cannot create the action's mount namespace: "
                        "unshare: %s (the executor needs CAP_SYS_ADMIN; in a "
                        "container see DOCKER.md)\n", strerror(errno));
        return -1;
    }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        fprintf(stderr, "executor: cannot set up the action's mount namespace: "
                        "mount private: %s (in a container the security profile "
                        "must allow mount, e.g. apparmor=unconfined: see "
                        "DOCKER.md)\n", strerror(errno));
        return -1;
    }
    for (int i = 0; i < N_CONTROL_DIRS; i++) {
        const char *d = CONTROL_DIRS[i];
        if (access(d, F_OK) != 0) continue;
        if (mount(d, d, NULL, MS_BIND | MS_REC, NULL) != 0) { perror("bind"); return -1; }
        if (mount(NULL, d, NULL, MS_REMOUNT | MS_BIND | MS_REC | MS_RDONLY | MS_NOSUID, NULL) != 0) {
            perror("remount ro"); return -1;
        }
    }

    /* Optional per-profile read-only filesystem. When the profile declares
     * `writable` paths, make the whole mount namespace read-only and carve out
     * exactly those paths read-write - a per-script ProtectSystem=strict, beyond
     * DAC. Opt-in: profiles with no `writable` are unaffected. Fail closed: if the
     * confinement cannot be established, do not run the action. Done here, before
     * the cap drop and uid switch, while we still hold CAP_SYS_ADMIN as root. */
    if (p->nwritable > 0) {
        if (mount_ro_recursive("/") != 0) {
            perror("executor: read-only filesystem (writable needs kernel >= 5.12)");
            return -1;
        }
        for (int i = 0; i < p->nwritable; i++) {
            const char *w = p->writable[i];
            if (access(w, F_OK) != 0) continue;   /* declared path absent: nothing to carve */
            if (mount(w, w, NULL, MS_BIND | MS_REC, NULL) != 0) {
                perror("executor: bind writable"); return -1;
            }
            if (mount(NULL, w, NULL, MS_REMOUNT | MS_BIND, NULL) != 0) {
                perror("executor: remount writable rw"); return -1;
            }
        }
        /* Private scratch /tmp so a confined script has somewhere to write
         * without declaring it (like systemd PrivateTmp). Best-effort. */
        if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, NULL) != 0)
            perror("executor: private /tmp (continuing)");
        /* Re-assert control/state dirs read-only, in case a writable path covered
         * one: an action must never be able to write the control plane. */
        for (int i = 0; i < N_CONTROL_DIRS; i++) {
            const char *d = CONTROL_DIRS[i];
            if (access(d, F_OK) != 0) continue;
            if (mount(d, d, NULL, MS_BIND | MS_REC, NULL) != 0) { perror("bind control"); return -1; }
            if (mount(NULL, d, NULL, MS_REMOUNT | MS_BIND | MS_REC | MS_RDONLY | MS_NOSUID, NULL) != 0) {
                perror("remount control ro"); return -1;
            }
        }
    }

    /* Drop the bounding set to exactly the profile's caps. Fail closed if a
     * capability that is in the set cannot be dropped (no CAP_SETPCAP, as in a
     * container started with cap_drop ALL): a root action that execs with
     * no_new_privileges off would otherwise regain every capability left in
     * the bounding set, beyond what its profile declares. A capability this
     * kernel does not know (PR_CAPBSET_READ fails) is not in the set. */
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        int keep = 0;
        for (int i = 0; i < p->ncaps; i++) {
            cap_value_t cv;
            if (cap_from_name(p->caps[i], &cv) == 0 && (int)cv == cap) { keep = 1; break; }
        }
        if (keep || prctl(PR_CAPBSET_READ, cap, 0, 0, 0) != 1) continue;
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
            int e = errno;
            char *cn = cap_to_name((cap_value_t)cap);   /* "cap_chown": shown as in agent.conf */
            for (char *q = cn; q && *q; q++) *q = (char)toupper((unsigned char)*q);
            fprintf(stderr, "executor: cannot drop %s from the capability bounding "
                            "set: %s (the executor needs CAP_SETPCAP; in a container "
                            "see DOCKER.md)\n", cn ? cn : "a capability", strerror(e));
            if (cn) cap_free(cn);
            return -1;
        }
    }

    /* run_as: switch gid/uid, keeping caps across the transition. */
    if (p->run_as[0]) {
        uid_t uid; gid_t gid;
        struct passwd *pw = getpwnam(p->run_as);
        if (pw) {
            uid = pw->pw_uid; gid = pw->pw_gid;
            if (user_env_from(pw, ue) != 0) return -1;
        } else {
            /* Numeric uid. run_as is validated at config load as a name or all
             * digits; here it is digits. Parse manually rather than strtol -
             * under _GNU_SOURCE, strtol redirects to the C23 __isoc23_strtol,
             * which is a glibc-2.38 symbol and would raise the package's libc
             * floor (breaking installs on older stable releases). */
            unsigned long v = 0;
            for (const char *q = p->run_as; *q; q++) {
                if (*q < '0' || *q > '9') {
                    fprintf(stderr, "executor: unknown run_as '%s'\n", p->run_as);
                    return -1;
                }
                if (v > (ULONG_MAX - 9) / 10) {
                    fprintf(stderr, "executor: run_as '%s' out of range\n", p->run_as);
                    return -1;
                }
                v = v * 10 + (unsigned long)(*q - '0');
            }
            /* Never let a large numeric run_as silently truncate (e.g. to uid 0,
             * root). Config load applies the same bound, but re-check here: the
             * executor must not trust that the value reaching it was validated. */
            if ((unsigned long)(uid_t)v != v || (unsigned long)(gid_t)v != v) {
                fprintf(stderr, "executor: run_as '%s' out of range for uid/gid\n",
                        p->run_as);
                return -1;
            }
            uid = (uid_t)v; gid = (gid_t)v;
            /* HOME/USER/LOGNAME for a numeric run_as come from that uid's passwd
             * entry if it has one; with none they are left unset. Only the
             * environment uses this lookup: supplementary groups for a numeric
             * run_as are unchanged (none). */
            if (user_env_from(getpwuid(uid), ue) != 0) return -1;
        }
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) { perror("executor: keepcaps"); return -1; }
        if (setgroups(0, NULL) != 0) { perror("executor: setgroups"); return -1; }
        /* Set the run_as user's supplementary groups. Fail closed if this fails:
         * running with no supplementary groups (the setgroups(0) result) instead
         * of the user's would be a privilege-correctness gap, not a safe default. */
        if (pw && initgroups(p->run_as, gid) != 0) { perror("initgroups"); return -1; }
        if (setgid(gid) != 0) { perror("setgid"); return -1; }
        if (setuid(uid) != 0) { perror("setuid"); return -1; }
    }

    /* Set the final cap set, and raise ambient so caps survive exec when the
     * action runs as a non-root run_as. */
    cap_t caps = cap_init();
    if (!caps) { perror("cap_init"); return -1; }
    if (p->ncaps > 0) {
        cap_value_t cvs[MAX_CAPS]; int nc = 0;
        for (int i = 0; i < p->ncaps && nc < MAX_CAPS; i++)
            if (cap_from_name(p->caps[i], &cvs[nc]) == 0) nc++;
        cap_set_flag(caps, CAP_PERMITTED,   nc, cvs, CAP_SET);
        cap_set_flag(caps, CAP_EFFECTIVE,   nc, cvs, CAP_SET);
        cap_set_flag(caps, CAP_INHERITABLE, nc, cvs, CAP_SET);
    }
    if (cap_set_proc(caps) != 0) { perror("cap_set_proc"); cap_free(caps); return -1; }
    cap_free(caps);
    for (int i = 0; i < p->ncaps; i++) {
        cap_value_t cv;
        if (cap_from_name(p->caps[i], &cv) == 0)
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cv, 0, 0);
    }

    if (p->nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
    return 0;
}

/* ---- confidential run input (T-013): the per-run directory -------------- */
/* For an input=fields script the executor, as root and before it forks the
 * action, makes a directory <socket dir>/input/<reqid>.<random> (mode 0700),
 * writes one file per field into it (mode 0600, created O_EXCL|O_NOFOLLOW
 * relative to the directory's fd), then hands the files and the directory to
 * the run_as user with fchown. It exists before the profile's mount namespace
 * is made, so it is visible (read-only) inside a `writable` profile too. After
 * the action is reaped, however it ended, the handler removes it; a directory
 * left by a crash is removed at the next start-up. */

typedef struct {
    int   active;                          /* made: must be removed */
    char  name[INPUT_NAME_MAX + 18];       /* "<reqid|run>.<16 hex>" */
    char  path[PATH_MAX];
    dev_t dev;
    ino_t ino;
} input_dir_t;

/* Remove `name` inside the directory open as dfd, and everything under it,
 * without following a symbolic link: every step is relative to a directory fd
 * opened with O_NOFOLLOW, so an entry the action replaced with a link is
 * unlinked as a link, never followed. Root does this inside a directory the
 * run_as user owns; nothing the user put there can steer it elsewhere. Returns
 * 0 when the entry is gone (or was never there), -1 otherwise (errno set). */
static int remove_tree_at(int dfd, const char *name, int depth) {
    int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return 0;
        if (errno == ENOTDIR || errno == ELOOP) {
            if (unlinkat(dfd, name, 0) == 0 || errno == ENOENT) return 0;
        }
        return -1;
    }
    if (depth >= RMTREE_MAX_DEPTH) { close(fd); errno = ELOOP; return -1; }
    DIR *d = fdopendir(fd);
    if (!d) { int e = errno; close(fd); errno = e; return -1; }
    /* A few passes: a process the action left behind may still be adding
     * entries. What survives is removed at the next start-up. */
    for (int pass = 0; pass < 3; pass++) {
        rewinddir(d);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            (void)remove_tree_at(dirfd(d), de->d_name, depth + 1);
        }
        if (unlinkat(dfd, name, AT_REMOVEDIR) == 0 || errno == ENOENT) {
            closedir(d);
            return 0;
        }
        if (errno != ENOTEMPTY && errno != EEXIST) break;
    }
    int e = errno;
    closedir(d);
    errno = e;
    return -1;
}

/* Set up <socket dir>/input, the parent of every per-run input directory
 * (/run/ctrl-exec-agent/input under the shipped unit, the executor's runtime
 * directory), and remove anything a crash left in it. The socket directory
 * must belong to this process's user and be writable by no one else, so no one
 * else can replace the 'input' entry; 'input' is made 0711 so the run_as user
 * can reach its own directory by name while no one can list which runs exist.
 * Returns an O_CLOEXEC fd on it (handlers inherit it through fork), or -1 with
 * the reason on stderr, in which case input=fields runs are refused. */
static int input_base_init(const char *sockpath, char *base, size_t bl) {
    const char *slash = strrchr(sockpath, '/');
    if (sockpath[0] != '/' || !slash) {
        fprintf(stderr, "ctrl-exec-executor: socket path '%s' is not absolute; "
                        "input=fields runs will be refused\n", sockpath);
        return -1;
    }
    char sdir[PATH_MAX];
    size_t n = (size_t)(slash - sockpath);
    if (n == 0) n = 1;                                  /* a socket in "/" */
    if (n >= sizeof(sdir) - 8) {
        fprintf(stderr, "ctrl-exec-executor: socket directory too long; "
                        "input=fields runs will be refused\n");
        return -1;
    }
    memcpy(sdir, sockpath, n);
    sdir[n] = '\0';
    snprintf(base, bl, "%s%sinput", sdir, n == 1 ? "" : "/");

    struct stat st;
    int pfd = open(sdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (pfd < 0 || fstat(pfd, &st) != 0) {
        fprintf(stderr, "ctrl-exec-executor: '%s': %s; input=fields runs will be refused\n",
                sdir, strerror(errno));
        if (pfd >= 0) close(pfd);
        return -1;
    }
    if (st.st_uid != geteuid() || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        fprintf(stderr, "ctrl-exec-executor: '%s' must be owned by uid %lu and not "
                        "group/other-writable; input=fields runs will be refused\n",
                sdir, (unsigned long)geteuid());
        close(pfd);
        return -1;
    }
    if (mkdirat(pfd, "input", 0711) != 0 && errno != EEXIST) {
        fprintf(stderr, "ctrl-exec-executor: cannot create '%s': %s; input=fields runs "
                        "will be refused\n", base, strerror(errno));
        close(pfd);
        return -1;
    }
    int bfd = openat(pfd, "input", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(pfd);
    if (bfd < 0 || fstat(bfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || fchmod(bfd, 0711) != 0) {
        fprintf(stderr, "ctrl-exec-executor: '%s' is not a directory owned by uid %lu; "
                        "input=fields runs will be refused\n", base, (unsigned long)geteuid());
        if (bfd >= 0) close(bfd);
        return -1;
    }

    /* Start-up sweep: nothing in here belongs to a live run yet. */
    int sfd = openat(bfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = sfd >= 0 ? fdopendir(sfd) : NULL;
    if (!d) {
        if (sfd >= 0) close(sfd);
        fprintf(stderr, "ctrl-exec-executor: cannot read '%s': %s; input=fields runs "
                        "will be refused\n", base, strerror(errno));
        close(bfd);
        return -1;
    }
    int removed = 0, left = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (remove_tree_at(bfd, de->d_name, 0) == 0) removed++; else left++;
    }
    closedir(d);
    if (removed)
        fprintf(stderr, "ctrl-exec-executor: removed %d stale input director%s from '%s'\n",
                removed, removed == 1 ? "y" : "ies", base);
    if (left)
        fprintf(stderr, "ctrl-exec-executor: could not remove %d entr%s in '%s'\n",
                left, left == 1 ? "y" : "ies", base);
    return bfd;
}

/* The uid and gid the action will run as, resolved as apply_profile resolves
 * them (a passwd name, else an all-digits id), or this process's own when the
 * profile has no run_as. The input directory and files are handed to these;
 * the child checks after the privilege drop that the directory it is given is
 * owned by the uid it then runs as. Returns 0, or -1 if run_as is unknown. */
static int run_as_ids(const profile_t *p, uid_t *uid, gid_t *gid) {
    if (!p->run_as[0]) { *uid = geteuid(); *gid = getegid(); return 0; }
    struct passwd *pw = getpwnam(p->run_as);
    if (pw) { *uid = pw->pw_uid; *gid = pw->pw_gid; return 0; }
    unsigned long v = 0;
    for (const char *q = p->run_as; *q; q++) {
        if (*q < '0' || *q > '9') return -1;
        if (v > (ULONG_MAX - 9) / 10) return -1;
        v = v * 10 + (unsigned long)(*q - '0');
    }
    if ((unsigned long)(uid_t)v != v || (unsigned long)(gid_t)v != v) return -1;
    *uid = (uid_t)v; *gid = (gid_t)v;
    return 0;
}

/* Make the per-run directory for an input=fields run and write the fields into
 * it, then give it to uid/gid. Order: mkdirat 0700 (root-owned, so nothing else
 * can enter while it is filled), openat O_NOFOLLOW + fstat, then per field
 * openat(O_CREAT|O_EXCL|O_NOFOLLOW) 0600 + fchmod + write + fchown, and fchown
 * of the directory last. Returns 0, or -1 with the reason in why (naming a
 * field, never a value); id->active says whether there is a directory to
 * remove either way. */
static int prepare_fields_dir(int bfd, const char *base, const char *reqid,
                              const view_t *names, const view_t *vals, uint32_t nf,
                              uid_t uid, gid_t gid, input_dir_t *id,
                              char *why, size_t wl) {
    unsigned char rnd[8];
    int rfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (rfd < 0 || read_all(rfd, rnd, sizeof(rnd)) != 0) {
        snprintf(why, wl, "executor: cannot prepare the input directory: no randomness\n");
        if (rfd >= 0) close(rfd);
        return -1;
    }
    close(rfd);
    /* The reqid names the directory only when it is a plain token. */
    const char *comp = "run";
    size_t rl = strlen(reqid);
    if (rl >= 1 && rl <= INPUT_NAME_MAX) {
        int ok = 1;
        for (size_t i = 0; i < rl; i++)
            if (!(isalnum((unsigned char)reqid[i]) || reqid[i] == '_' || reqid[i] == '-')) ok = 0;
        if (ok) comp = reqid;
    }
    snprintf(id->name, sizeof(id->name), "%s.%02x%02x%02x%02x%02x%02x%02x%02x", comp,
             rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]);
    int w = snprintf(id->path, sizeof(id->path), "%s/%s", base, id->name);
    if (w < 0 || (size_t)w >= sizeof(id->path)) {
        snprintf(why, wl, "executor: cannot prepare the input directory: path too long\n");
        return -1;
    }
    if (mkdirat(bfd, id->name, 0700) != 0) {
        snprintf(why, wl, "executor: cannot create the input directory: %s\n", strerror(errno));
        return -1;
    }
    id->active = 1;
    struct stat st;
    int dfd = openat(bfd, id->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0 || fstat(dfd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || fchmod(dfd, 0700) != 0) {
        snprintf(why, wl, "executor: cannot prepare the input directory: %s\n", strerror(errno));
        if (dfd >= 0) close(dfd);
        return -1;
    }
    for (uint32_t i = 0; i < nf; i++) {
        char fname[INPUT_NAME_MAX + 1];
        memcpy(fname, names[i].p, names[i].len);         /* validated: 1..64 */
        fname[names[i].len] = '\0';
        int fd = openat(dfd, fname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        int e = 0;
        if (fd < 0) e = errno;
        else if (fchmod(fd, 0600) != 0 || write_all(fd, vals[i].p, vals[i].len) != 0 ||
                 fchown(fd, uid, gid) != 0) e = errno;
        if (fd >= 0 && close(fd) != 0 && !e) e = errno;
        if (e) {
            snprintf(why, wl, "executor: cannot create input file '%s': %s\n", fname, strerror(e));
            close(dfd);
            return -1;
        }
    }
    if (fchown(dfd, uid, gid) != 0) {
        snprintf(why, wl, "executor: cannot hand the input directory to the run_as user: %s\n",
                 strerror(errno));
        close(dfd);
        return -1;
    }
    id->dev = st.st_dev;
    id->ino = st.st_ino;
    close(dfd);
    return 0;
}

/* What the action gets beyond the fixed environment, for raw and fields. */
typedef struct {
    char              *env[3];   /* "CTRL_EXEC_CONTEXT=..", "CTRL_EXEC_INPUT=..", NULL */
    const input_dir_t *dir;      /* the fields directory to verify, or NULL */
} run_input_t;

/* Per-stream cap on captured stdout/stderr. The request frame is bounded
 * (MAX_FRAME) but the action's output was not: a chatty or runaway allowlisted
 * script (a log dump, `yes`, a misbehaving job) could grow the ROOT executor's
 * RSS without bound until OOM. Cap each stream and keep draining the pipe past
 * the cap (so the child never blocks on a full pipe), appending a one-time
 * truncation marker. 16 MiB matches the request cap. */
#define MAX_OUTPUT  (16 * 1024 * 1024)

/* Grow-on-demand byte buffer. */
typedef struct { char *p; size_t len, cap; } buf_t;
static int buf_add(buf_t *b, const char *d, size_t n) {
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->len + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) return -1;
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n; b->p[b->len] = '\0';
    return 0;
}

/* Close every fd from 3 up in the action's process, just before execve, so the
 * action holds only stdin, stdout and stderr (T-051). The executor's own fds are
 * already close-on-exec or closed in the child (the connection socket from
 * accept4 SOCK_CLOEXEC, the listening socket, the input base fd, the pipes'
 * other ends); this also covers anything the executor inherited from whatever
 * started it, anything a library opened without O_CLOEXEC, and any fd a later
 * change forgets. close_range(2) is called through syscall() (kernel 5.9+, no
 * glibc 2.34 symbol, keeping the libc floor low). Without it: close each fd
 * listed in /proc/self/fd, and failing that every fd below the open-files
 * limit. */
static void close_inherited_fds(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, ~0U, 0U) == 0) return;
#endif
    DIR *d = opendir("/proc/self/fd");
    if (d) {
        int self = dirfd(d);
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            /* Digits only, parsed by hand (not strtol: see run_as below). */
            long fd = 0;
            const char *q = de->d_name;
            if (!*q) continue;
            for (; *q >= '0' && *q <= '9' && fd < INT_MAX / 10; q++) fd = fd * 10 + (*q - '0');
            if (*q || fd < 3 || fd == self) continue;
            close((int)fd);
        }
        closedir(d);
    } else {
        struct rlimit rl;
        long max = (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
                   ? (long)rl.rlim_cur : 65536;
        for (long fd = 3; fd < max; fd++) close((int)fd);
    }
}

/* Run path/argv under profile p, feeding `indata` to stdin, capturing stdout and
 * stderr concurrently (select, to avoid pipe-buffer deadlock). ownership_strict
 * is agent.conf script_ownership (T-054): 1 refuses a script that breaks the
 * ownership rule, 0 (warn) runs it. */
static int run_with_profile(const profile_t *p, const char *path, char *const argv[],
                            const char *indata, size_t inlen, int allow_unpriv,
                            int ownership_strict, const run_input_t *ri,
                            int *exit_out, buf_t *out, buf_t *err) {
    int o[2], e[2], in[2];
    if (pipe(o) || pipe(e) || pipe(in)) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* The handler ignores SIGPIPE (see handle_conn); an ignored disposition
         * survives execve, so restore the default before anything else. The
         * action always starts with SIGPIPE at SIG_DFL, whatever the executor
         * itself was started with (systemd sets SIG_IGN, OpenRC does not). */
        signal(SIGPIPE, SIG_DFL);
        dup2(in[0], 0); dup2(o[1], 1); dup2(e[1], 2);
        close(in[0]); close(in[1]); close(o[0]); close(o[1]); close(e[0]); close(e[1]);
        user_env_t ue;
        if (apply_profile(p, allow_unpriv, &ue) != 0) _exit(126);
        /* Ownership rule (T-045): the script and every directory on its path
         * owned by root and not group/other-writable. Checked here, after the
         * profile is applied, so it sees the mount namespace and identity the
         * exec will use.
         *
         * With script_ownership = strict a script that breaks the rule (DENY)
         * or cannot be checked (UNKNOWN) is refused. With warn (T-054, the
         * default) both run: the front end logged the reason when it loaded
         * the allowlist, and self-check / check-path show it. Nothing is
         * written here in warn mode: fd 2 is already the action's stderr pipe,
         * so a line here would reach the caller as the script's own stderr.
         * UNKNOWN runs too in warn mode: it means the walk could not open a
         * component (missing, or not searchable by the run_as user), and the
         * access()/stat()/execve() below then fail with the real error. */
        char why[PATH_MAX + 256];
        struct stat fst;
        int tc = script_trust_check(path, why, sizeof(why), &fst);
        if (tc == 1 && ownership_strict) {
            dprintf(2, "executor: script not permitted: %s\n", why);
            _exit(126);
        }
        /* Clear diagnostic instead of a silent exit-127: a run_as user that
         * cannot read+exec the script is the most common cause. The script's
         * permissions must allow the profile's run_as user (e.g. a script owned
         * root:prosody mode 0750 for run_as=prosody). */
        if (access(path, X_OK) != 0) {
            dprintf(2, "executor: '%s' is not executable by the profile's run_as "
                       "user (%s) - check the script's owner/group/mode\n",
                    path, strerror(errno));
            _exit(126);
        }
        if (tc != 0 && ownership_strict) {
            dprintf(2, "executor: script not permitted: cannot check %s\n", why);
            _exit(126);
        }
        if (tc != 0) {
            /* warn mode, the rule not met: fst was not filled by the walk (it
             * stopped before the script), so bind the exec below to what the
             * path names now. The dev/ino re-check then still holds the exec
             * to this file, but the file itself is no longer protected: a user
             * who can write the script or a directory on its path can change
             * it before this stat, or swap it between this stat and execve's
             * own lookup - the trade-off script_ownership = warn accepts
             * (docs/SECURITY.md). */
            if (stat(path, &fst) != 0) {
                dprintf(2, "executor: cannot stat '%s': %s\n", path, strerror(errno));
                _exit(126);
            }
        }
#ifdef CE_TEST_SEAM
        /* Test build only: block between the check and the exec until the test
         * has written a byte to this fifo (the swap-after-check test). */
        const char *pf = getenv("CE_TEST_PAUSE_FIFO");
        if (pf && *pf) {
            int ffd = open(pf, O_RDONLY | O_CLOEXEC);
            char b;
            if (ffd >= 0) { if (read(ffd, &b, 1) < 0) { /* proceed */ } close(ffd); }
        }
#endif
        /* Exec by path, bound to the file just checked. The checked file is the
         * one the walk opened (fstat on its fd); the path must still name that
         * same file (dev/ino) or nothing runs. When the rule passed, between
         * this stat and execve only root can change what the path names: every
         * directory on it has just been shown to be root-owned and not
         * group/other-writable. (In warn mode with the rule not met, see the
         * stat above: that guarantee is what warn gives up.)
         *
         * Not fexecve/execveat(AT_EMPTY_PATH): for a '#!' script the kernel then
         * hands the interpreter "/dev/fd/N" as the script name instead of the
         * path, so $0, dirname "$0", BASH_SOURCE and FindBin all change (and it
         * needs the fd left open across exec and /proc mounted in the action's
         * namespace). Scripts here are mostly bash or perl, and scripts commonly
         * find their own files with dirname "$0" or re-run themselves via "$0"
         * (the agent-file-transfer plugin does), so fd-exec would break them.
         * The ownership rule is what keeps a non-root user from swapping the
         * file; exec-by-fd would add protection only against root, which
         * writes scripts.conf anyway. */
        struct stat pst;
        if (stat(path, &pst) != 0 || pst.st_dev != fst.st_dev || pst.st_ino != fst.st_ino) {
            dprintf(2, "executor: script not permitted: '%s' changed while it was "
                       "being checked\n", path);
            _exit(126);
        }
        /* input=fields (T-013): the path handed over in CTRL_EXEC_INPUT must
         * name, in this namespace and under this identity, the directory the
         * handler prepared (same dev/ino), owned by the uid the action now
         * runs as. */
        if (ri && ri->dir) {
            struct stat ist;
            if (stat(ri->dir->path, &ist) != 0 || !S_ISDIR(ist.st_mode) ||
                ist.st_dev != ri->dir->dev || ist.st_ino != ri->dir->ino ||
                ist.st_uid != getuid()) {
                dprintf(2, "executor: the input directory is not reachable as prepared "
                           "inside the action's profile\n");
                _exit(126);
            }
        }
        /* Sanitised environment: the executor never trusts its own inherited
         * env for the action. The script receives request context on stdin
         * (not via the environment), so a fixed PATH avoids passing the
         * loader and shell variables (LD_PRELOAD, LD_LIBRARY_PATH, BASH_ENV,
         * IFS, PERL5LIB, ...) as attack surface to script interpreters running
         * under the profile. Under a run_as user with a passwd entry, HOME,
         * USER and LOGNAME are added from that entry (T-004), so the user's
         * tools (docker, git, ssh) find their home; nothing caller-controlled
         * enters the environment. For input=raw and input=fields (T-013) the
         * front end's context JSON (no input, no caller token) is added as
         * CTRL_EXEC_CONTEXT, and for fields the directory path as
         * CTRL_EXEC_INPUT; input values never enter the environment. */
        char *clean_env[8];
        int ne = 0;
        clean_env[ne++] = (char *)"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        if (ue.set) {
            clean_env[ne++] = ue.home;
            clean_env[ne++] = ue.user;
            clean_env[ne++] = ue.logname;
        }
        for (int i = 0; ri && i < 2 && ri->env[i]; i++) clean_env[ne++] = ri->env[i];
        clean_env[ne] = NULL;
        /* The action gets stdin, stdout and stderr (the pipes above) and no
         * other descriptor of the executor's (T-051). */
        close_inherited_fds();
        execve(path, argv, clean_env);
        dprintf(2, "executor: exec '%s' failed: %s\n", path, strerror(errno));
        _exit(127);
    }
    close(in[0]); close(o[1]); close(e[1]);

    /* Feed stdin from the same select loop that drains stdout and stderr, with
     * non-blocking writes. A blocking write of the whole payload first would
     * deadlock against an action that fills its output pipe before reading
     * stdin, or never reads it: each side waits on its own write (T-036).
     * stdin is closed once the payload is written, or as soon as a write fails.
     * An action that exits (or closes stdin) without reading its context makes
     * the write fail with EPIPE. That is normal, not an error: the run's result
     * is still its exit status and output. SIGPIPE is ignored in the handler, so
     * the write returns EPIPE here instead of killing the handler before it can
     * send the response. */
    int infd = in[1];
    size_t inoff = 0;
    if (!indata || inlen == 0 || fcntl(infd, F_SETFL, O_NONBLOCK) != 0) {
        /* Nothing to send - or, if the fd cannot be made non-blocking, send
         * nothing rather than risk the deadlock: the action sees EOF. */
        close(infd); infd = -1;
    }

    int fds[2] = { o[0], e[0] };
    buf_t *bufs[2] = { out, err };
    int trunc[2] = { 0, 0 };
    int open_n = 2;
    while (open_n > 0 || infd >= 0) {
        fd_set rd, wr; FD_ZERO(&rd); FD_ZERO(&wr); int mx = -1;
        for (int i = 0; i < 2; i++) if (fds[i] >= 0) { FD_SET(fds[i], &rd); if (fds[i] > mx) mx = fds[i]; }
        if (infd >= 0) { FD_SET(infd, &wr); if (infd > mx) mx = infd; }
        if (mx < 0) break;
        if (select(mx + 1, &rd, &wr, NULL, NULL) < 0) { if (errno == EINTR) continue; break; }
        if (infd >= 0 && FD_ISSET(infd, &wr)) {
            ssize_t w = write(infd, indata + inoff, inlen - inoff);
            if (w > 0) inoff += (size_t)w;
            if ((w < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)
                || inoff >= inlen) {
                close(infd); infd = -1;
            }
        }
        for (int i = 0; i < 2; i++) {
            if (fds[i] >= 0 && FD_ISSET(fds[i], &rd)) {
                char tmp[8192];
                ssize_t r = read(fds[i], tmp, sizeof(tmp));
                if (r > 0) {
                    buf_t *b = bufs[i];
                    if (b->len < MAX_OUTPUT) {
                        size_t room = MAX_OUTPUT - b->len;
                        buf_add(b, tmp, (size_t)r < room ? (size_t)r : room);
                    } else if (!trunc[i]) {
                        buf_add(b, "\n[output truncated]\n", 20);
                        trunc[i] = 1;
                    }
                    /* Past the cap: keep reading to drain the pipe so the child
                     * never blocks on a full pipe, but discard the data. */
                } else { close(fds[i]); fds[i] = -1; open_n--; }
            }
        }
    }
    int status = 0;
    waitpid(pid, &status, 0);
    *exit_out = WIFEXITED(status) ? WEXITSTATUS(status) : 126;
    return 0;
}

/* Handle one connection: read request, resolve, run, write response. The parsed
 * agent.conf (cfg) is supplied by the serve loop - parsed once at startup and
 * reloaded only on mtime change - so each forked handler does not re-parse it or
 * re-allocate the large config_t per connection. The security property is
 * unchanged: path, profile and input mode are re-derived from this OWN
 * root-owned config, never from the message. input_bfd/input_base are the
 * per-run input directories' parent (-1 when it could not be set up). */
static void handle_conn(int cfd, config_t *cfg, const char *scripts_conf,
                        int allow_unpriv, int input_bfd, const char *input_base) {
    /* A write to a pipe or socket whose reader has gone must fail with EPIPE,
     * not kill this handler: the stdin write to an action that exited without
     * reading it raced the action's exit, and the default SIGPIPE killed the
     * handler before it wrote any response, so the front-end saw "executor
     * closed before responding" for a run that had succeeded (T-034). The
     * action itself gets SIG_DFL back in run_with_profile before execve. */
    signal(SIGPIPE, SIG_IGN);
    uint32_t total;
    if (read_u32(cfd, &total) != 0 || total == 0 || total > MAX_FRAME) return;
    unsigned char *frame = malloc(total);
    if (!frame) return;
    if (read_all(cfd, frame, total) != 0) { wipe(frame, total); free(frame); return; }

    uint32_t off = 0;
    int v2 = (total >= 4 && be32(frame) == FRAME_V2_MAGIC);
    if (v2) off = 4;
    char *reqid  = take_field(frame, total, &off, NULL);
    uint32_t displen = 0;
    char *disp   = take_field(frame, total, &off, &displen);
    char *script = take_field(frame, total, &off, NULL);
    uint32_t inlen = 0;
    char *indata = take_field(frame, total, &off, &inlen);
    int bad = (!reqid || !disp || !script || !indata);

    /* v2: the context for CTRL_EXEC_CONTEXT - an environment string, so no NUL. */
    char *ctxenv = NULL;
    uint32_t ctxlen = 0;
    if (v2 && !bad) {
        ctxenv = take_field(frame, total, &off, &ctxlen);
        if (!ctxenv || strlen(ctxenv) != ctxlen) bad = 1;
    }

    char *argv[MAX_ARGS + 2]; int argc = 0;
    uint32_t na = 0;
    if (!bad) {
        if (off + 4 > total) bad = 1;
        else { na = ((uint32_t)frame[off]<<24)|((uint32_t)frame[off+1]<<16)|
                    ((uint32_t)frame[off+2]<<8)|frame[off+3]; off += 4; }
    }
    if (!bad && na > MAX_ARGS) bad = 1;
    if (!bad) {
        argv[argc++] = script;                       /* argv[0] = script path (set below) */
        for (uint32_t i = 0; i < na && !bad; i++) {
            char *a = take_field(frame, total, &off, NULL);
            if (!a) { bad = 1; break; }
            argv[argc++] = a;
        }
        argv[argc] = NULL;
    }

    /* v2: the input fields, read in place and bounded before any is used: the
     * count first, then each name's form, duplicates, the running byte total,
     * and nothing may follow the last field. Errors name fields, never values. */
    view_t inames[MAX_INPUT_FIELDS], ivals[MAX_INPUT_FIELDS];
    uint32_t nf = 0;
    char ierr[200] = "";
    if (v2 && !bad) {
        if (total - off < 4) bad = 1;
        else { nf = be32(frame + off); off += 4; }
        if (!bad && nf > MAX_INPUT_FIELDS)
            snprintf(ierr, sizeof(ierr), "executor: input has more than %d fields\n", MAX_INPUT_FIELDS);
        uint64_t sum = 0;
        for (uint32_t i = 0; !bad && !ierr[0] && i < nf; i++) {
            if (take_view(frame, total, &off, &inames[i]) != 0 ||
                take_view(frame, total, &off, &ivals[i]) != 0) { bad = 1; break; }
            if (!input_name_ok((const char *)inames[i].p, inames[i].len)) {
                snprintf(ierr, sizeof(ierr), "executor: input field name is invalid "
                         "(allowed: A-Z a-z 0-9 _ . -, 1-64 characters)\n");
                break;
            }
            for (uint32_t j = 0; j < i; j++)
                if (inames[j].len == inames[i].len &&
                    memcmp(inames[j].p, inames[i].p, inames[i].len) == 0) {
                    snprintf(ierr, sizeof(ierr), "executor: input field '%.*s' appears more than once\n",
                             (int)inames[i].len, (const char *)inames[i].p);
                    break;
                }
            sum += ivals[i].len;
            if (!ierr[0] && sum > MAX_INPUT_BYTES)
                snprintf(ierr, sizeof(ierr), "executor: input exceeds the executor's limit of %d bytes\n",
                         MAX_INPUT_BYTES);
        }
        if (!bad && !ierr[0] && off != total) bad = 1;   /* trailing bytes */
    }

    int ecode = -1; buf_t out = {0}, err = {0};
    input_dir_t idir;
    memset(&idir, 0, sizeof(idir));
    run_input_t ri;
    memset(&ri, 0, sizeof(ri));
    if (bad) {
        /* v1 keeps its old text; an agent that sent v2 reads that text as "this
         * executor predates input" (Exec::Agent::ExecClient). */
        const char *m = v2 ? "executor: malformed input frame\n" : "executor: malformed request\n";
        buf_add(&err, m, strlen(m));
        ecode = -1;
    } else if (ierr[0]) {
        buf_add(&err, ierr, strlen(ierr));
    } else {
        /* Re-derive path + profile + input mode from our OWN cached root-owned
         * config; never trust the message. The window between path_in_dirs()
         * (realpath) below and the later execve is not reachable by a non-root
         * user: before the exec, run_with_profile checks that the script and
         * every directory on its path are root-owned and not group/other-
         * writable (T-045), and that the path still names the file it checked.
         * With script_ownership = warn (T-054) a script that breaks that rule
         * runs anyway, and then a user who can write it or a directory on its
         * path can change what runs - the documented trade-off of warn. */
        char spath[VALLEN], pname[NAMELEN], imode[INPUT_MODE_LEN], dlist[VALLEN];
        profile_t *p = NULL;
        char dwhy[160];
        /* The output mode is not needed here (see output_mode_ok): NULL. */
        if (!find_script(scripts_conf, script, spath, sizeof(spath), pname, sizeof(pname),
                         imode, sizeof(imode), NULL, 0, dlist, sizeof(dlist))) {
            buf_add(&err, "executor: script not permitted\n", 31);
        } else if (dlist[0] && !(disp_id_ok(disp, displen) && strlen(disp) == displen
                                 && dispatchers_has(dlist, disp))) {
            /* dispatchers= (T-063), from OUR scripts.conf. The id is the
             * agent's statement of which trusted dispatcher it authenticated
             * for this run (the frame's disp field); this process has no TLS
             * view, so it cannot verify that statement, only hold the agent to
             * the root-owned limit. An empty or malformed id never matches. */
            if (disp_id_ok(disp, displen) && strlen(disp) == displen)
                snprintf(dwhy, sizeof(dwhy), "executor: script not permitted for dispatcher "
                         "'%s'\n", disp);
            else
                snprintf(dwhy, sizeof(dwhy), "executor: script not permitted: the request "
                         "names no valid dispatcher\n");
            buf_add(&err, dwhy, strlen(dwhy));
        } else if (!path_in_dirs(spath, cfg)) {
            buf_add(&err, "executor: script not in script_dirs\n", 36);
        } else if (!(p = find_profile(cfg, pname))) {
            /* No built-in fallback: an undefined profile (including 'default'
             * when [profile default] is not configured) is refused, never run
             * under an implicit root context. */
            buf_add(&err, "executor: undefined profile\n", 28);
        } else {
            /* Delivery by the mode in OUR scripts.conf (imode). A request that
             * does not fit it is refused here, before anything is created or
             * forked. context: stdin is the frame's stdin, as before. raw: stdin
             * is the one field's bytes. fields: stdin is empty and the fields
             * are files. raw and fields add CTRL_EXEC_CONTEXT. */
            const char *feed = indata;
            size_t feedlen = inlen;
            int fields = 0;
            char why[PATH_MAX + 256] = "";
            if (strcmp(imode, "context") != 0) {
                if (!v2) {
                    /* A v1 frame: the agent holds this script as input=context
                     * (it sends v2 for any other mode), so it and this executor
                     * read scripts.conf differently - an agent that has not
                     * picked up an edit, or one that predates input= (the frame
                     * cannot tell which) (T-059). */
                    snprintf(why, sizeof(why), "executor: scripts.conf declares '%s' input=%s, "
                             "but the request carried no input; if scripts.conf changed, "
                             "run 'systemctl reload ctrl-exec-agent'\n", script, imode);
                } else if (ctxlen == 0) {
                    snprintf(why, sizeof(why), "executor: malformed input frame\n");
                } else if (strcmp(imode, "fields") == 0) {
                    fields = 1;
                    feed = NULL; feedlen = 0;
                } else if (strcmp(imode, "raw") == 0) {
                    if (nf != 1)
                        snprintf(why, sizeof(why), "executor: script takes input=raw: exactly one "
                                 "input field is required, got %u\n", (unsigned)nf);
                    else { feed = (const char *)ivals[0].p; feedlen = ivals[0].len; }
                } else {                                    /* raw:<name> */
                    const char *want = imode + 4;
                    size_t wl = strlen(want);
                    uint32_t k = nf;
                    for (uint32_t i = 0; i < nf; i++)
                        if (inames[i].len == wl && memcmp(inames[i].p, want, wl) == 0) { k = i; break; }
                    if (k == nf)
                        snprintf(why, sizeof(why), "executor: script takes input=raw:%s but input "
                                 "field '%s' is missing\n", want, want);
                    else { feed = (const char *)ivals[k].p; feedlen = ivals[k].len; }
                }
                if (!why[0]) {
                    static const char pre[] = "CTRL_EXEC_CONTEXT=";
                    ri.env[0] = malloc(sizeof(pre) + ctxlen);
                    if (!ri.env[0]) snprintf(why, sizeof(why), "executor: out of memory\n");
                    else { memcpy(ri.env[0], pre, sizeof(pre) - 1);
                           memcpy(ri.env[0] + sizeof(pre) - 1, ctxenv, (size_t)ctxlen + 1); }
                }
            }
            if (!why[0] && fields) {
                uid_t uid; gid_t gid;
                if (input_bfd < 0)
                    snprintf(why, sizeof(why), "executor: input=fields is unavailable: the input "
                             "directory could not be set up at start-up (see the executor's log)\n");
                else if (run_as_ids(p, &uid, &gid) != 0)
                    snprintf(why, sizeof(why), "executor: unknown run_as '%s'\n", p->run_as);
                else if (prepare_fields_dir(input_bfd, input_base, reqid, inames, ivals, nf,
                                            uid, gid, &idir, why, sizeof(why)) == 0) {
                    static const char pre[] = "CTRL_EXEC_INPUT=";
                    ri.env[1] = malloc(sizeof(pre) + strlen(idir.path));
                    if (!ri.env[1]) snprintf(why, sizeof(why), "executor: out of memory\n");
                    else { memcpy(ri.env[1], pre, sizeof(pre) - 1);
                           strcpy(ri.env[1] + sizeof(pre) - 1, idir.path); }
                    ri.dir = &idir;
                }
            }
            if (why[0]) {
                buf_add(&err, why, strlen(why));
            } else {
                argv[0] = spath;                      /* argv[0] = resolved path */
                run_with_profile(p, spath, argv, feed, feedlen, allow_unpriv,
                                 cfg->ownership_strict,
                                 (ri.env[0] || ri.dir) ? &ri : NULL, &ecode, &out, &err);
            }
            /* The action has been reaped (or never started): the directory goes
             * whatever way it ended. */
            if (idir.active && remove_tree_at(input_bfd, idir.name, 0) != 0)
                fprintf(stderr, "ctrl-exec-executor: could not remove input directory "
                                "'%s/%s': %s\n", input_base, idir.name, strerror(errno));
        }
    }

    int32_t ec = (int32_t)ecode;
    write_u32(cfd, (uint32_t)ec);
    write_u32(cfd, (uint32_t)out.len); if (out.len) write_all(cfd, out.p, out.len);
    write_u32(cfd, (uint32_t)err.len); if (err.len) write_all(cfd, err.p, err.len);

    free(out.p); free(err.p);
    free(ri.env[0]); free(ri.env[1]);
    if (indata) wipe(indata, inlen);                 /* context-mode stdin holds input */
    free(reqid); free(disp); free(indata); free(ctxenv);
    for (int i = 1; i < argc; i++) free(argv[i]);   /* argv[0] is spath/script (freed via script) */
    free(script);
    wipe(frame, total);
    free(frame);
}

static int cmd_serve(const char *sockpath, const char *agent_conf,
                     const char *scripts_conf, const char *peer_user) {
    int allow_unpriv = (getenv("CTRL_EXEC_EXEC_ALLOW_UNPRIV") != NULL);
    if (geteuid() != 0 && !allow_unpriv) {
        fprintf(stderr, "ctrl-exec-executor: serve must run as root\n");
        return 1;
    }
    struct passwd *pw = getpwnam(peer_user);
    if (!pw) { fprintf(stderr, "ctrl-exec-executor: unknown peer user '%s'\n", peer_user); return 1; }
    uid_t peer_uid = pw->pw_uid;

    int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sfd < 0) { perror("socket"); return 1; }
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(sockpath) >= sizeof(addr.sun_path)) { fprintf(stderr, "socket path too long\n"); return 1; }
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    unlink(sockpath);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
    /* Owner = peer user, mode 0600: only that uid (and root) may connect. */
    if (chown(sockpath, peer_uid, pw->pw_gid) != 0) perror("chown");
    if (chmod(sockpath, 0600) != 0) perror("chmod");
    if (listen(sfd, 16) != 0) { perror("listen"); return 1; }

    /* Parse agent.conf ONCE here, not per connection. Each forked handler then
     * inherits the parsed config through fork (copy-on-write) instead of doing a
     * fresh ~8MB calloc + parse on every request. Reloaded below only when
     * agent.conf's mtime changes, so an admin edit still takes effect. */
    config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg || parse_agent_conf(agent_conf, cfg) != 0) {
        fprintf(stderr, "ctrl-exec-executor: cannot parse '%s'\n", agent_conf);
        free(cfg); close(sfd); return 1;
    }
    struct stat cst;
    time_t cfg_mtime = (stat(agent_conf, &cst) == 0) ? cst.st_mtime : 0;

    /* Confidential run input (T-013): the parent of the per-run input=fields
     * directories, swept of anything a crash left behind. */
    char input_base[PATH_MAX] = "";
    int input_bfd = input_base_init(sockpath, input_base, sizeof(input_base));

    for (;;) {
        /* SOCK_CLOEXEC: the connection must never reach the action. An action
         * holding it could write its own result frame (any exit status and
         * output) to the agent, or corrupt the real one (T-051). */
        int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); break; }

        struct ucred uc; socklen_t ucl = sizeof(uc);
        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &uc, &ucl) != 0 ||
            (uc.uid != peer_uid && uc.uid != 0)) {
            close(cfd); continue;             /* reject: not the front-end uid */
        }

        /* Reload agent.conf if it changed on disk (cheap stat per connection).
         * Parse into a fresh config and swap only on success, so a mid-edit /
         * broken file leaves the last-good config in place (fail-safe). */
        if (stat(agent_conf, &cst) == 0 && cst.st_mtime != cfg_mtime) {
            cfg_mtime = cst.st_mtime;
            config_t *nc = calloc(1, sizeof(*nc));
            if (nc && parse_agent_conf(agent_conf, nc) == 0) {
                free(cfg); cfg = nc;
            } else {
                free(nc);   /* keep serving with the previous valid config */
            }
        }

        pid_t pid = fork();
        if (pid == 0) {
            close(sfd);
            handle_conn(cfd, cfg, scripts_conf, allow_unpriv, input_bfd, input_base);
            close(cfd);
            _exit(0);
        }
        close(cfd);
        while (waitpid(-1, NULL, WNOHANG) > 0) {}   /* reap finished handlers */
    }
    free(cfg);
    if (input_bfd >= 0) close(input_bfd);
    close(sfd);
    return 0;
}

/* Started with stdin, stdout or stderr closed, the executor's next socket,
 * pipe or directory fd would take that number: its error messages would then
 * go into whatever holds fd 2 (possibly the agent connection), and the
 * action's pipe wiring could collide with its own fds. Fill any closed one of
 * 0-2 with /dev/null before anything else is opened; if that fails, stop. */
static int ensure_stdio_open(void) {
    for (int fd = 0; fd <= 2; fd++) {
        if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) continue;
        int n = open("/dev/null", O_RDWR);
        if (n != fd) { if (n >= 0) close(n); return -1; }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (ensure_stdio_open() != 0) return 1;
    if (argc == 5 && strcmp(argv[1], "resolve") == 0)
        return cmd_resolve(argv[2], argv[3], argv[4]);
    if (argc == 6 && strcmp(argv[1], "serve") == 0)
        return cmd_serve(argv[2], argv[3], argv[4], argv[5]);
    if (argc == 3 && strcmp(argv[1], "check-path") == 0)
        return cmd_check_path(argv[2]);

    fprintf(stderr,
        "ctrl-exec-executor - privileged executor for ctrl-exec-agent\n"
        "usage: ctrl-exec-executor resolve <agent.conf> <scripts.conf> <script-name>\n"
        "       ctrl-exec-executor serve   <socket> <agent.conf> <scripts.conf> <peer-user>\n"
        "       ctrl-exec-executor check-path <script-path>\n");
    return 1;
}
