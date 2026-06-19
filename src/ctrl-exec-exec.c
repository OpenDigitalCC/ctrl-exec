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
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sys/capability.h>

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

/* ====================================================================== *
 *  serve mode: socket + peer-cred + framed request -> profiled exec
 * ====================================================================== */

/* Wire framing. Request (front-end -> executor), all big-endian length-prefixed:
 *   [u32 total] [u32 len][reqid] [u32 len][disp] [u32 len][script]
 *   [u32 len][stdin] [u32 argc] argc*([u32 len][arg])
 * Response (executor -> front-end):
 *   [i32 exit] [u32 len][stdout] [u32 len][stderr]
 * Length-prefixed throughout so args/stdin may hold arbitrary bytes (args still
 * cannot contain NUL - execv requires C strings - but stdin may). */

#define MAX_FRAME   (16 * 1024 * 1024)   /* 16MB request cap */
#define MAX_ARGS    256

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

/* ---- privileged child setup ------------------------------------------- */
/* Apply the profile in the forked child just before exec. Returns 0 or -1.
 * COMPILE-VERIFIED; the namespace/cap/setuid paths require root + CAP_SYS_ADMIN
 * and are exercised on a real host (see the on-host test plan). With
 * allow_unpriv and a non-root euid (test only), the privileged steps are
 * skipped and only no_new_privileges is applied. */
static int apply_profile(const profile_t *p, int allow_unpriv) {
    int is_root = (geteuid() == 0);

    if (!is_root) {
        if (!allow_unpriv) { fprintf(stderr, "executor: must run as root\n"); return -1; }
        if (p->run_as[0] || p->ncaps > 0) {
            fprintf(stderr, "executor: profile needs privilege but euid != 0\n");
            return -1;
        }
        if (p->nnp && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return -1;
        return 0;
    }

    /* Control-plane integrity: control/state dirs read-only in this action's
     * mount namespace. CAP_SYS_ADMIN required - we have it as root. */
    if (unshare(CLONE_NEWNS) != 0) { perror("unshare"); return -1; }
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) { perror("mount private"); return -1; }
    for (int i = 0; i < N_CONTROL_DIRS; i++) {
        const char *d = CONTROL_DIRS[i];
        if (access(d, F_OK) != 0) continue;
        if (mount(d, d, NULL, MS_BIND | MS_REC, NULL) != 0) { perror("bind"); return -1; }
        if (mount(NULL, d, NULL, MS_REMOUNT | MS_BIND | MS_REC | MS_RDONLY | MS_NOSUID, NULL) != 0) {
            perror("remount ro"); return -1;
        }
    }

    /* Drop the bounding set to exactly the profile's caps. */
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        int keep = 0;
        for (int i = 0; i < p->ncaps; i++) {
            cap_value_t cv;
            if (cap_from_name(p->caps[i], &cv) == 0 && (int)cv == cap) { keep = 1; break; }
        }
        if (!keep) prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
    }

    /* run_as: switch gid/uid, keeping caps across the transition. */
    if (p->run_as[0]) {
        uid_t uid; gid_t gid;
        struct passwd *pw = getpwnam(p->run_as);
        if (pw) { uid = pw->pw_uid; gid = pw->pw_gid; }
        else {
            char *end; long v = strtol(p->run_as, &end, 10);
            if (*end || v < 0) { fprintf(stderr, "executor: unknown run_as '%s'\n", p->run_as); return -1; }
            uid = (uid_t)v; gid = (gid_t)v;
        }
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) return -1;
        if (setgroups(0, NULL) != 0) return -1;
        if (pw) initgroups(p->run_as, gid);
        if (setgid(gid) != 0) { perror("setgid"); return -1; }
        if (setuid(uid) != 0) { perror("setuid"); return -1; }
    }

    /* Set the final cap set, and raise ambient so caps survive exec when the
     * action runs as a non-root run_as. */
    cap_t caps = cap_init();
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

/* Run path/argv under profile p, feeding `indata` to stdin, capturing stdout and
 * stderr concurrently (select, to avoid pipe-buffer deadlock). */
static int run_with_profile(const profile_t *p, const char *path, char *const argv[],
                            const char *indata, size_t inlen, int allow_unpriv,
                            int *exit_out, buf_t *out, buf_t *err) {
    int o[2], e[2], in[2];
    if (pipe(o) || pipe(e) || pipe(in)) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        dup2(in[0], 0); dup2(o[1], 1); dup2(e[1], 2);
        close(in[0]); close(in[1]); close(o[0]); close(o[1]); close(e[0]); close(e[1]);
        if (apply_profile(p, allow_unpriv) != 0) _exit(126);
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
        execv(path, argv);
        dprintf(2, "executor: exec '%s' failed: %s\n", path, strerror(errno));
        _exit(127);
    }
    close(in[0]); close(o[1]); close(e[1]);
    if (indata && inlen) (void)!write_all(in[1], indata, inlen);
    close(in[1]);

    int fds[2] = { o[0], e[0] };
    buf_t *bufs[2] = { out, err };
    int open_n = 2;
    while (open_n > 0) {
        fd_set rd; FD_ZERO(&rd); int mx = -1;
        for (int i = 0; i < 2; i++) if (fds[i] >= 0) { FD_SET(fds[i], &rd); if (fds[i] > mx) mx = fds[i]; }
        if (mx < 0) break;
        if (select(mx + 1, &rd, NULL, NULL, NULL) < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < 2; i++) {
            if (fds[i] >= 0 && FD_ISSET(fds[i], &rd)) {
                char tmp[8192];
                ssize_t r = read(fds[i], tmp, sizeof(tmp));
                if (r > 0) buf_add(bufs[i], tmp, (size_t)r);
                else { close(fds[i]); fds[i] = -1; open_n--; }
            }
        }
    }
    int status = 0;
    waitpid(pid, &status, 0);
    *exit_out = WIFEXITED(status) ? WEXITSTATUS(status) : 126;
    return 0;
}

/* Handle one connection: read request, resolve, run, write response. */
static void handle_conn(int cfd, const char *agent_conf, const char *scripts_conf,
                        int allow_unpriv) {
    uint32_t total;
    if (read_u32(cfd, &total) != 0 || total == 0 || total > MAX_FRAME) return;
    unsigned char *frame = malloc(total);
    if (!frame) return;
    if (read_all(cfd, frame, total) != 0) { free(frame); return; }

    uint32_t off = 0;
    char *reqid  = take_field(frame, total, &off, NULL);
    char *disp   = take_field(frame, total, &off, NULL);
    char *script = take_field(frame, total, &off, NULL);
    uint32_t inlen = 0;
    char *indata = take_field(frame, total, &off, &inlen);
    int bad = (!reqid || !disp || !script || !indata);

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

    int ecode = -1; buf_t out = {0}, err = {0};
    if (bad) { buf_add(&err, "executor: malformed request\n", 28); ecode = -1; }
    else {
        /* Re-derive path + profile from our OWN config; never trust the message. */
        config_t *c = calloc(1, sizeof(*c));
        char spath[VALLEN], pname[NAMELEN];
        profile_t builtin, *p = NULL;
        if (!c || parse_agent_conf(agent_conf, c) != 0) {
            buf_add(&err, "executor: config error\n", 23);
        } else if (!find_script(scripts_conf, script, spath, sizeof(spath), pname, sizeof(pname))) {
            buf_add(&err, "executor: script not permitted\n", 31);
        } else if (!path_in_dirs(spath, c)) {
            buf_add(&err, "executor: script not in script_dirs\n", 36);
        } else if (!(p = find_profile(c, pname)) && strcmp(pname, "default") != 0) {
            buf_add(&err, "executor: undefined profile\n", 28);
        } else {
            if (!p) { memset(&builtin, 0, sizeof(builtin));
                      snprintf(builtin.name, sizeof(builtin.name), "default");
                      builtin.nnp = 1; p = &builtin; }
            argv[0] = spath;                          /* argv[0] = resolved path */
            run_with_profile(p, spath, argv, indata, inlen, allow_unpriv, &ecode, &out, &err);
        }
        free(c);
    }

    int32_t ec = (int32_t)ecode;
    write_u32(cfd, (uint32_t)ec);
    write_u32(cfd, (uint32_t)out.len); if (out.len) write_all(cfd, out.p, out.len);
    write_u32(cfd, (uint32_t)err.len); if (err.len) write_all(cfd, err.p, err.len);

    free(out.p); free(err.p);
    free(reqid); free(disp); free(indata);
    for (int i = 1; i < argc; i++) free(argv[i]);   /* argv[0] is spath/script (freed via script) */
    free(script);
    free(frame);
}

static int cmd_serve(const char *sockpath, const char *agent_conf,
                     const char *scripts_conf, const char *peer_user) {
    int allow_unpriv = (getenv("CTRL_EXEC_EXEC_ALLOW_UNPRIV") != NULL);
    if (geteuid() != 0 && !allow_unpriv) {
        fprintf(stderr, "ctrl-exec-exec: serve must run as root\n");
        return 1;
    }
    struct passwd *pw = getpwnam(peer_user);
    if (!pw) { fprintf(stderr, "ctrl-exec-exec: unknown peer user '%s'\n", peer_user); return 1; }
    uid_t peer_uid = pw->pw_uid;

    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
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

    for (;;) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); break; }

        struct ucred uc; socklen_t ucl = sizeof(uc);
        if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &uc, &ucl) != 0 ||
            (uc.uid != peer_uid && uc.uid != 0)) {
            close(cfd); continue;             /* reject: not the front-end uid */
        }
        pid_t pid = fork();
        if (pid == 0) { close(sfd); handle_conn(cfd, agent_conf, scripts_conf, allow_unpriv); close(cfd); _exit(0); }
        close(cfd);
        while (waitpid(-1, NULL, WNOHANG) > 0) {}   /* reap finished handlers */
    }
    close(sfd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "resolve") == 0)
        return cmd_resolve(argv[2], argv[3], argv[4]);
    if (argc == 6 && strcmp(argv[1], "serve") == 0)
        return cmd_serve(argv[2], argv[3], argv[4], argv[5]);

    fprintf(stderr,
        "ctrl-exec-exec - privileged executor for ctrl-exec-agent\n"
        "usage: ctrl-exec-exec resolve <agent.conf> <scripts.conf> <script-name>\n"
        "       ctrl-exec-exec serve   <socket> <agent.conf> <scripts.conf> <peer-user>\n");
    return 1;
}
