/*
 * locked-helper -- mediated placement operations for `locked`.
 *
 * Build: clang -O2 -Wall -Wextra -framework Foundation -o locked-helper locked-helper.m
 *
 * `locked` seals directories with append-only / immutable BSD flags. Removing,
 * renaming or trashing an entry inside such a directory needs the parent's flag
 * word lifted for the duration of one syscall. Doing that from bash means the
 * window is bounded by a shell's liveness and every step re-resolves a path,
 * which is exactly the TOCTOU / parent-swap residual this binary exists to
 * close.
 *
 * The whole window -- clear flags, operate, restore flags -- lives here, on
 * open file descriptors. Once a descriptor exists for a node, that node is
 * never named again except for error text and for the two calls that have no
 * fd-based form (lchflags on a symlink, and the path handed to the trash
 * service). Every other operation is an *at() call against a held fd.
 *
 * Exit codes are interface; the bash caller dispatches on them:
 *   0  ok
 *   2  identity refusal -- nothing was touched
 *   3  operation failed -- the window was restored
 *   4  usage error or not root
 *   5  flag restore FAILED -- a window is LEFT OPEN; `window-open\t<path>`
 *      lines on stdout tell the bash backstop what to re-seal
 *   6  operation completed but the parent's entry list changed in a way the
 *      operation does not account for; `anomaly` lines on stdout
 *
 * Node identity (`--parent-id`, `--target-id`, `--src-id`, and what the `id`
 * verb prints) is `<volume uuid>:<inode>`, or `<st_dev>:<inode>` on a
 * filesystem that reports no volume uuid (devfs) and in records written
 * before locked 0.6.0. st_dev is NOT a volume key: APFS assigns it at mount
 * in mount order, so it can name a different volume after a reboot. The
 * volume uuid is a property of the volume itself and survives one. `-` means
 * "no expectation". Both `:` and `.` are accepted as the separator on input;
 * output always uses `:`.
 *
 * stdout carries only tab-separated machine lines (binurl, anomaly,
 * window-open), plus the one bare `<id>` line the `id` verb prints. stderr
 * carries one lowercase prose line per error.
 *
 * Entry names on `anomaly` lines are backslash-escaped (\\, \t, \n, \r, \xNN
 * for other control bytes) so a hostile filename cannot forge or split a
 * machine line. Names passed in by the caller are rejected outright if they
 * contain a tab or newline, so the `binurl` path never needs escaping.
 *
 * C style throughout; Objective-C appears only around the Foundation trash
 * call, which has no C equivalent.
 */

#import <Foundation/Foundation.h>

#include <sys/types.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/stdio.h>
#include <sys/wait.h>

#include <copyfile.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

/* ---- constants ---------------------------------------------------------- */

#define EX_HELPER_OK       0
#define EX_HELPER_IDENT    2
#define EX_HELPER_OPFAIL   3
#define EX_HELPER_USAGE    4
#define EX_HELPER_WINOPEN  5
#define EX_HELPER_ANOMALY  6

/* The flags that block unlink/rename of a node, or of entries in a directory.
 * Nothing else in the flag word is ever touched: hidden, nodump, opaque and
 * the archived bit survive the window untouched because we restore the whole
 * saved word rather than re-deriving it. */
#define BLOCKING_FLAGS (SF_APPEND | UF_APPEND | SF_IMMUTABLE | UF_IMMUTABLE)

/* Recursion cap for the rm walk. One directory fd is held per level, so the
 * walk costs at most MAX_DEPTH + a small constant descriptors. */
#define MAX_DEPTH 64

/* ---- diagnostics -------------------------------------------------------- */

static void errf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void
errf(const char *fmt, ...)
{
	va_list ap;

	/* stdout carries machine lines; keep the two streams ordered for a
	 * caller that merges them. */
	fflush(stdout);
	fputs("locked-helper: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void
usage(void)
{
	fputs(
"usage: locked-helper rm --parent <dir> --parent-id <id|-> --name <entry>\n"
"                        --target-id <id|-> [--recursive]\n"
"       locked-helper mv --parent <dir> --parent-id <id|-> --name <old>\n"
"                        --target-id <id|-> --dest-parent <dir>\n"
"                        --dest-parent-id <id|-> --dest-name <new>\n"
"       locked-helper trash --parent <dir> --parent-id <id|-> --name <entry>\n"
"                           --target-id <id|-> --uid <uid> --gid <gid>\n"
"                           --home <dir>\n"
"       locked-helper copy --src <path> --src-id <id|-> --dest <path>\n"
"       locked-helper xattrs-from --src <path> --src-id <id|->\n"
"                                 --dest <path>\n"
"       locked-helper id <path>\n",
	    stderr);
}

/* ---- lifted seals ------------------------------------------------------- */

/*
 * Every node whose flag word is currently lifted is registered here. The
 * normal paths restore through window_restore()/target_restore(), but an
 * abnormal exit -- an allocation failure, a SIGINT from the terminal, a
 * SIGTERM -- must not be allowed to walk away from a directory it unsealed.
 * Both routes go through live_restore(), so there is exactly one place that
 * puts a flag word back.
 *
 * Two parents plus one target is the worst case. Nodes unsealed inside the
 * recursive walk are deliberately NOT registered: they are being deleted, and
 * one unsealed leaf inside a half-removed tree is not a protection loss worth
 * a slot.
 */
#define MAX_LIVE 4

typedef struct {
	int		 fd;		/* -1 => act on `path` with lchflags */
	int		 used;
	uint32_t	 saved;
	const char	*path;
	size_t		 plen;
} live_t;

static live_t g_live[MAX_LIVE];

static int
live_add(int fd, uint32_t saved, const char *path)
{
	int i;

	for (i = 0; i < MAX_LIVE; i++) {
		if (g_live[i].used)
			continue;
		g_live[i].fd = fd;
		g_live[i].used = 1;
		g_live[i].saved = saved;
		g_live[i].path = path;
		g_live[i].plen = strlen(path);
		return (i);
	}
	return (-1);
}

/*
 * A renamed node no longer answers to the name it was registered under. Only
 * the fd-less (symlink) case actually reads the path back, but the signal
 * handler could fire at any instant after the rename, so the registry is
 * corrected the moment the name changes rather than at restore time.
 */
static void
live_repath(int i, const char *path)
{
	if (i < 0 || !g_live[i].used)
		return;
	g_live[i].path = path;
	g_live[i].plen = strlen(path);
}

/* Drop a slot without touching the node: for a seal that was never lifted. */
static void
live_forget(int i)
{
	if (i >= 0)
		g_live[i].used = 0;
}

static int
live_put_back(int i)
{
	if (g_live[i].fd >= 0)
		return (fchflags(g_live[i].fd, g_live[i].saved));
	return (lchflags(g_live[i].path, g_live[i].saved));
}

/* Normal path. Returns 0 on success, -1 after reporting a failed restore. */
static int
live_restore(int i, const char *reported_as)
{
	const char *p;

	if (i < 0 || !g_live[i].used)
		return (0);
	g_live[i].used = 0;
	if (live_put_back(i) == 0)
		return (0);
	p = reported_as != NULL ? reported_as : g_live[i].path;
	errf("cannot restore flags on %s: %s", p, strerror(errno));
	printf("window-open\t%s\n", p);
	return (-1);
}

/* Abnormal path. Returns nonzero if any restore failed. */
static int
live_restore_all(void)
{
	int i, bad = 0;

	for (i = 0; i < MAX_LIVE; i++) {
		if (!g_live[i].used)
			continue;
		g_live[i].used = 0;
		if (live_put_back(i) != 0) {
			printf("window-open\t%s\n", g_live[i].path);
			bad = 1;
		}
	}
	return (bad);
}

static void
fatal(const char *msg)
{
	int bad;

	errf("%s", msg);
	bad = live_restore_all();
	fflush(stdout);
	_exit(bad ? EX_HELPER_WINOPEN : EX_HELPER_OPFAIL);
}

/*
 * Signal path. Only async-signal-safe calls: fchflags/lchflags/write/_exit,
 * and the path length was measured at registration so strlen is not needed.
 */
static void
on_signal(int sig)
{
	int i, bad = 0;

	(void)sig;
	for (i = 0; i < MAX_LIVE; i++) {
		if (!g_live[i].used)
			continue;
		g_live[i].used = 0;
		if (live_put_back(i) != 0) {
			(void)write(STDOUT_FILENO, "window-open\t", 12);
			(void)write(STDOUT_FILENO, g_live[i].path,
			    g_live[i].plen);
			(void)write(STDOUT_FILENO, "\n", 1);
			bad = 1;
		}
	}
	_exit(bad ? EX_HELPER_WINOPEN : EX_HELPER_OPFAIL);
}

/* ---- small utilities ---------------------------------------------------- */

/* dup(2) clears FD_CLOEXEC; every descriptor in this process keeps it. */
static int
dup_cloexec(int fd)
{
	return (fcntl(fd, F_DUPFD_CLOEXEC, 0));
}

static void *
xmalloc(size_t n)
{
	void *p = malloc(n);

	if (p == NULL)
		fatal("out of memory");
	return (p);
}

static char *
xstrdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = xmalloc(n);

	memcpy(p, s, n);
	return (p);
}

/* Used only for error text, for lchflags on a symlink, and for the single
 * path handed to the trash service. Never for path resolution of an op. */
static char *
join_path(const char *dir, const char *name)
{
	size_t dl = strlen(dir);
	size_t nl = strlen(name);
	int slash = (dl > 0 && dir[dl - 1] == '/') ? 0 : 1;
	char *p = xmalloc(dl + (size_t)slash + nl + 1);

	memcpy(p, dir, dl);
	if (slash)
		p[dl] = '/';
	memcpy(p + dl + (size_t)slash, name, nl);
	p[dl + (size_t)slash + nl] = '\0';
	return (p);
}

/* ---- node identity ------------------------------------------------------ */

typedef struct {
	int	given;
	int	by_vol;		/* the expectation names a volume uuid */
	uuid_t	vol;
	dev_t	dev;		/* used only when by_vol is 0 */
	ino_t	ino;
} nodeid_t;

/* A volume's uuid, or nothing when the filesystem reports none. */
typedef struct {
	int	given;
	uuid_t	u;
} voluuid_t;

/*
 * getattrlist's fixed-shape answer. ATTR_CMN_RETURNED_ATTRS plus
 * FSOPT_PACK_INVAL_ATTRS is what makes it fixed: an unsupported attribute is
 * then packed as zeroes instead of shifting everything after it, and the
 * returned mask says whether the volume answered at all.
 */
struct volattrbuf {
	uint32_t	len;
	attribute_set_t	returned;
	uuid_t		uuid;
} __attribute__((packed, aligned(4)));

static void
vol_attrlist(struct attrlist *al)
{
	memset(al, 0, sizeof(*al));
	al->bitmapcount = ATTR_BIT_MAP_COUNT;
	al->commonattr = ATTR_CMN_RETURNED_ATTRS;
	al->volattr = ATTR_VOL_INFO | ATTR_VOL_UUID;
}

static void
vol_take(const struct volattrbuf *b, voluuid_t *out)
{
	out->given = 0;
	if ((b->returned.volattr & ATTR_VOL_UUID) == 0)
		return;
	memcpy(out->u, b->uuid, sizeof(uuid_t));
	out->given = 1;
}

/*
 * The uuid of the volume a node lives on. Asked of the node itself, not of a
 * mount point: getattrlist answers with the containing volume for any path or
 * descriptor (probed 2026-09-09). devfs reports none, which leaves `given` 0
 * and sends the caller to the st_dev form.
 */
static int
vol_uuid_fd(int fd, voluuid_t *out)
{
	struct attrlist al;
	struct volattrbuf b;

	out->given = 0;
	vol_attrlist(&al);
	if (fgetattrlist(fd, &al, &b, sizeof(b), FSOPT_PACK_INVAL_ATTRS) != 0)
		return (-1);
	vol_take(&b, out);
	return (0);
}

/* dirfd may be AT_FDCWD when the path is absolute, which is the only shape
 * the callers pass. FSOPT_NOFOLLOW: a symlink's own volume, never its
 * target's. */
static int
vol_uuid_at(int dirfd, const char *name, voluuid_t *out)
{
	struct attrlist al;
	struct volattrbuf b;

	out->given = 0;
	vol_attrlist(&al);
	if (getattrlistat(dirfd, name, &al, &b, sizeof(b),
	    FSOPT_NOFOLLOW | FSOPT_PACK_INVAL_ATTRS) != 0)
		return (-1);
	vol_take(&b, out);
	return (0);
}

/*
 * How to re-ask the kernel about a node without naming a path this process
 * does not already hold: a descriptor when there is one, else a (dirfd, name)
 * pair for the *at() call. A symlink or a socket never yields a descriptor,
 * so the pair is the only form available for those.
 */
typedef struct {
	int		 fd;	/* -1 when there is none */
	int		 dirfd;
	const char	*name;
} nodeat_t;

static nodeat_t
at_fd(int fd)
{
	nodeat_t a;

	a.fd = fd;
	a.dirfd = -1;
	a.name = NULL;
	return (a);
}

static nodeat_t
at_name(int dirfd, const char *name)
{
	nodeat_t a;

	a.fd = -1;
	a.dirfd = dirfd;
	a.name = name;
	return (a);
}

/*
 * "-" means "no expectation". Both "<vol>:<ino>" and "<vol>.<ino>" are
 * accepted: the bash side's records spell the separator with a dot while this
 * helper's own output and error text use the colon the header fixes. A uuid
 * contains neither, so the separator is unambiguous either way.
 */
static int
parse_id(const char *s, nodeid_t *out)
{
	uuid_string_t ub;
	char *end;
	unsigned long long iv;

	out->given = 0;
	out->by_vol = 0;
	out->dev = 0;
	out->ino = 0;
	memset(out->vol, 0, sizeof(out->vol));
	if (s == NULL || strcmp(s, "-") == 0)
		return (0);

	if (strlen(s) > 36 && (s[36] == ':' || s[36] == '.')) {
		memcpy(ub, s, 36);
		ub[36] = '\0';
		if (uuid_parse(ub, out->vol) != 0)
			return (-1);
		out->by_vol = 1;
		s += 37;
	} else {
		long long dv;

		errno = 0;
		dv = strtoll(s, &end, 10);
		if (end == s || errno != 0 || (*end != ':' && *end != '.'))
			return (-1);
		out->dev = (dev_t)dv;
		s = end + 1;
	}
	errno = 0;
	iv = strtoull(s, &end, 10);
	if (end == s || errno != 0 || *end != '\0')
		return (-1);

	out->ino = (ino_t)iv;
	out->given = 1;
	return (0);
}

/* The st_dev form: still what an in-window entry snapshot speaks, since those
 * comparisons never outlive one run of this process, and still the fallback
 * for a filesystem with no volume uuid. Printed UNSIGNED through uint32_t,
 * the way stat(1) prints it: dev_t is a signed 32-bit type, devfs's st_dev
 * has the high bit set, and a leading "-" would both disagree with every
 * record the bash side ever wrote and read as a uuid to its eye. */
static void
fmt_id(char *buf, size_t n, dev_t dev, ino_t ino)
{
	snprintf(buf, n, "%llu:%llu", (unsigned long long)(uint32_t)dev,
	    (unsigned long long)ino);
}

static void
fmt_vol_id(char *buf, size_t n, const uuid_t vol, ino_t ino)
{
	uuid_string_t u;

	uuid_unparse_upper(vol, u);
	snprintf(buf, n, "%s:%llu", u, (unsigned long long)ino);
}

/*
 * Identity gate. Every caller runs this BEFORE any flag word is cleared, so a
 * refusal leaves the filesystem exactly as it was found. `at` says how to
 * reach the node for its volume uuid; the volume is only asked for when the
 * expectation names one, and a volume that reports none while the record
 * names one is a mismatch, not a pass.
 */
static int
check_id(const char *what, const char *path, const nodeid_t *want,
    const struct stat *st, nodeat_t at)
{
	voluuid_t vol;
	char got[64], exp[64];
	int match;

	if (!want->given)
		return (0);

	vol.given = 0;
	if (want->by_vol) {
		if (at.fd >= 0)
			(void)vol_uuid_fd(at.fd, &vol);
		else
			(void)vol_uuid_at(at.dirfd, at.name, &vol);
		match = vol.given && uuid_compare(vol.u, want->vol) == 0 &&
		    st->st_ino == want->ino;
	} else {
		match = st->st_dev == want->dev && st->st_ino == want->ino;
	}
	if (match)
		return (0);

	if (want->by_vol) {
		if (vol.given)
			fmt_vol_id(got, sizeof(got), vol.u, st->st_ino);
		else
			snprintf(got, sizeof(got), "no-volume-uuid:%llu",
			    (unsigned long long)st->st_ino);
		fmt_vol_id(exp, sizeof(exp), want->vol, want->ino);
	} else {
		fmt_id(got, sizeof(got), st->st_dev, st->st_ino);
		fmt_id(exp, sizeof(exp), want->dev, want->ino);
	}
	errf("%s %s changed identity (%s expected %s)", what, path, got, exp);
	return (-1);
}

/* ---- directory entry snapshots ------------------------------------------ */

typedef struct {
	char	*name;
	dev_t	 dev;
	ino_t	 ino;
} entry_t;

typedef struct {
	entry_t	*v;
	size_t	 n;
	size_t	 cap;
} elist_t;

static void
elist_free(elist_t *l)
{
	size_t i;

	for (i = 0; i < l->n; i++)
		free(l->v[i].name);
	free(l->v);
	l->v = NULL;
	l->n = 0;
	l->cap = 0;
}

static void
elist_push(elist_t *l, const char *name, dev_t dev, ino_t ino)
{
	if (l->n == l->cap) {
		size_t cap = l->cap ? l->cap * 2 : 64;
		entry_t *v = realloc(l->v, cap * sizeof(*v));

		if (v == NULL)
			fatal("out of memory");
		l->v = v;
		l->cap = cap;
	}
	l->v[l->n].name = xstrdup(name);
	l->v[l->n].dev = dev;
	l->v[l->n].ino = ino;
	l->n++;
}

static int
entry_cmp(const void *a, const void *b)
{
	const entry_t *x = a, *y = b;

	return (strcmp(x->name, y->name));
}

/*
 * Snapshot a directory's entries as {name, dev:ino}. fdopendir() takes
 * ownership of the descriptor it is given, so it always gets a dup; the
 * caller's fd survives closedir().
 *
 * An entry that vanishes between readdir and fstatat is recorded as 0:0. If it
 * was already gone in the "before" pass too, both sides read 0:0 and no
 * spurious anomaly is raised; a genuine mid-window disappearance still shows.
 */
static int
snapshot(int dirfd, const char *path, elist_t *out)
{
	int dfd;
	DIR *dp;
	struct dirent *de;

	out->v = NULL;
	out->n = 0;
	out->cap = 0;

	dfd = dup_cloexec(dirfd);
	if (dfd < 0) {
		errf("cannot duplicate directory handle for %s: %s", path,
		    strerror(errno));
		return (-1);
	}
	dp = fdopendir(dfd);
	if (dp == NULL) {
		errf("cannot read directory %s: %s", path, strerror(errno));
		close(dfd);
		return (-1);
	}
	rewinddir(dp);
	while ((de = readdir(dp)) != NULL) {
		struct stat st;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		if (fstatat(dirfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
			elist_push(out, de->d_name, 0, 0);
		else
			elist_push(out, de->d_name, st.st_dev, st.st_ino);
	}
	closedir(dp);
	if (out->n > 1)
		qsort(out->v, out->n, sizeof(out->v[0]), entry_cmp);
	return (0);
}

/*
 * What the operation itself is expected to have changed in one parent. Any
 * difference beyond this is an anomaly: some other writer touched the
 * directory while its seal was lifted.
 */
typedef struct {
	const char	*gone;		/* entry this op removed, or NULL */
	const char	*added;		/* entry this op created, or NULL */
	dev_t		 add_dev;	/* identity the added entry must have */
	ino_t		 add_ino;
} expect_t;

/*
 * Sorted merge of before/after. Prints one line per unaccounted difference:
 *   anomaly\t-\t<name>\t<dev:ino>   entry disappeared
 *   anomaly\t+\t<name>\t<dev:ino>   entry appeared
 *   anomaly\t~\t<name>\t<dev:ino>   same name, different dev:ino
 * Returns the number of anomalies printed.
 */
/*
 * A filename is attacker-chosen and may contain a tab or a newline, either of
 * which would split or forge a machine line in the bash parser. Escape rather
 * than drop, so the alarm still names the entry recognizably.
 */
static void
print_escaped(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;

	for (; *p != '\0'; p++) {
		switch (*p) {
		case '\\':
			fputs("\\\\", stdout);
			break;
		case '\t':
			fputs("\\t", stdout);
			break;
		case '\n':
			fputs("\\n", stdout);
			break;
		case '\r':
			fputs("\\r", stdout);
			break;
		default:
			if (*p < 0x20 || *p == 0x7f)
				printf("\\x%02x", *p);
			else
				fputc((int)*p, stdout);
			break;
		}
	}
}

static void
print_anomaly(char kind, const char *name, dev_t dev, ino_t ino)
{
	char id[64];

	fmt_id(id, sizeof(id), dev, ino);
	printf("anomaly\t%c\t", kind);
	print_escaped(name);
	printf("\t%s\n", id);
}

static int
diff_report(const elist_t *before, const elist_t *after, const expect_t *exp)
{
	size_t i = 0, j = 0;
	int found = 0;

	while (i < before->n || j < after->n) {
		int c;

		if (i >= before->n)
			c = 1;
		else if (j >= after->n)
			c = -1;
		else
			c = strcmp(before->v[i].name, after->v[j].name);

		if (c < 0) {
			const entry_t *e = &before->v[i++];

			if (exp->gone != NULL && strcmp(exp->gone, e->name) == 0)
				continue;
			print_anomaly('-', e->name, e->dev, e->ino);
			found++;
		} else if (c > 0) {
			const entry_t *e = &after->v[j++];

			if (exp->added != NULL &&
			    strcmp(exp->added, e->name) == 0 &&
			    e->dev == exp->add_dev && e->ino == exp->add_ino)
				continue;
			print_anomaly('+', e->name, e->dev, e->ino);
			found++;
		} else {
			const entry_t *b = &before->v[i++];
			const entry_t *a = &after->v[j++];

			if (b->dev == a->dev && b->ino == a->ino)
				continue;
			print_anomaly('~', a->name, a->dev, a->ino);
			found++;
		}
	}
	return (found);
}

/* ---- the window --------------------------------------------------------- */

typedef struct {
	int		 fd;		/* held for the whole window */
	const char	*path;		/* error text only */
	struct stat	 st;
	uint32_t	 saved;		/* full flag word as found */
	int		 live;		/* registry slot while the seal is lifted */
	elist_t		 before;
	elist_t		 after;
} window_t;

static void
window_init(window_t *w)
{
	memset(w, 0, sizeof(*w));
	w->fd = -1;
	w->live = -1;
}

/*
 * Open the parent, verify its identity, and snapshot it. No flag is touched
 * here: a caller with two parents opens and verifies BOTH before clearing
 * EITHER, so an identity refusal never leaves a seal lifted.
 */
static int
window_open(window_t *w, const char *path, const nodeid_t *want)
{
	w->path = path;
	w->fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (w->fd < 0) {
		/* O_NOFOLLOW refuses a trailing symlink; the caller is required
		 * to canonicalize parent directories before it gets here. */
		if (errno == ELOOP || errno == ENOTDIR)
			errf("parent %s is not a directory or is a symlink; "
			    "it must be canonicalized first", path);
		else
			errf("cannot open parent %s: %s", path,
			    strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	if (fstat(w->fd, &w->st) != 0) {
		errf("cannot stat parent %s: %s", path, strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	if (check_id("parent", path, want, &w->st, at_fd(w->fd)) != 0)
		return (EX_HELPER_IDENT);
	w->saved = w->st.st_flags;
	if (snapshot(w->fd, path, &w->before) != 0)
		return (EX_HELPER_OPFAIL);
	return (EX_HELPER_OK);
}

/* Lift only the blocking bits, from the held fd. Nothing is re-resolved. */
static int
window_clear(window_t *w)
{
	int slot;

	if ((w->saved & BLOCKING_FLAGS) == 0)
		return (EX_HELPER_OK);
	/* Registered BEFORE the fchflags: if the process dies between the two
	 * the restore is a no-op, whereas the reverse order could lose it. */
	slot = live_add(w->fd, w->saved, w->path);
	if (slot < 0) {
		errf("too many lifted seals at once");
		return (EX_HELPER_OPFAIL);
	}
	if (fchflags(w->fd, w->saved & ~(uint32_t)BLOCKING_FLAGS) != 0) {
		errf("cannot lift flags on parent %s: %s", w->path,
		    strerror(errno));
		/* The word is untouched, so this is not an open window and must
		 * not raise the alarm that says one was left behind. */
		live_forget(slot);
		return (EX_HELPER_OPFAIL);
	}
	w->live = slot;
	return (EX_HELPER_OK);
}

/*
 * Restore the saved word on the same fd. A failure here is the one outcome
 * that leaves the filesystem less protected than it was found, so it prints
 * the machine line the bash backstop re-seals from and forces exit 5.
 */
static int
window_restore(window_t *w)
{
	int slot = w->live;

	w->live = -1;
	return (live_restore(slot, NULL));
}

static void
window_close(window_t *w)
{
	elist_free(&w->before);
	elist_free(&w->after);
	if (w->fd >= 0)
		close(w->fd);
	w->fd = -1;
}

/* ---- target handling ---------------------------------------------------- */

/*
 * A node we are about to unlink, rename or trash. `fd` is -1 when the node
 * could not be opened: a symlink (O_NOFOLLOW yields ELOOP) or a socket. Those
 * have no fd-based flag call, so they fall back to lchflags by name.
 */
typedef struct {
	int		 fd;
	struct stat	 st;
	uint32_t	 saved;
	int		 live;		/* registry slot while the seal is lifted */
	char		*path;		/* composed once, for the fallback */
} target_t;

static void
target_init(target_t *t)
{
	memset(t, 0, sizeof(*t));
	t->fd = -1;
	t->live = -1;
}

static void
target_close(target_t *t)
{
	if (t->fd >= 0)
		close(t->fd);
	t->fd = -1;
	free(t->path);
	t->path = NULL;
}

/*
 * Open and identity-check the named entry of an already-open parent. Called
 * before any flag word is lifted; opening for read needs no seal lifted.
 */
static int
target_open(target_t *t, int pfd, const char *ppath, const char *name,
    const nodeid_t *want)
{
	int flags = O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;

	t->path = join_path(ppath, name);

	if (fstatat(pfd, name, &t->st, AT_SYMLINK_NOFOLLOW) != 0) {
		errf("cannot stat %s: %s", t->path, strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	/* The volume comes from the held parent fd and the entry name, never
	 * from a re-resolved path -- the same *at() discipline as the stat
	 * above. For a symlink or a socket this is the only identity check
	 * there will be, since neither yields a descriptor. */
	if (check_id("target", t->path, want, &t->st, at_name(pfd, name)) != 0)
		return (EX_HELPER_IDENT);
	t->saved = t->st.st_flags;

	/* Neither a symlink nor a socket yields a descriptor; they take the
	 * lchflags fallback. */
	if (S_ISLNK(t->st.st_mode) || S_ISSOCK(t->st.st_mode))
		return (EX_HELPER_OK);
	if (S_ISDIR(t->st.st_mode))
		flags |= O_DIRECTORY;
	/* O_NONBLOCK so a fifo or a device node cannot stall the open. */
	t->fd = openat(pfd, name, flags);
	if (t->fd < 0) {
		/* The stat above said this was neither, so these errors mean
		 * the entry was swapped for a symlink or a socket in between.
		 * Refusing is the only safe reading of that. */
		if (errno == ELOOP || errno == ENXIO || errno == EOPNOTSUPP) {
			errf("target %s changed type between stat and open; "
			    "refusing", t->path);
			return (EX_HELPER_IDENT);
		}
		errf("cannot open %s: %s", t->path, strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	/* The fd is authoritative from here: re-check identity against what it
	 * actually points at, not against what the name resolved to. */
	if (fstat(t->fd, &t->st) != 0) {
		errf("cannot stat %s: %s", t->path, strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	if (check_id("target", t->path, want, &t->st, at_fd(t->fd)) != 0)
		return (EX_HELPER_IDENT);
	t->saved = t->st.st_flags;
	return (EX_HELPER_OK);
}

/*
 * Lift the node's own blocking bits so unlink/rename can proceed. Immutable
 * and append-only both refuse unlink and rename of the node itself, so both
 * are cleared.
 *
 * When there is no fd (symlink, socket) the only available call is lchflags on
 * the composed path. That re-resolves the name for the duration of one syscall
 * immediately before the unlinkat, so a swap in that nanosecond window would
 * unseal a different node of the same name. Accepted residual: macOS has no
 * chflagsat(), and the alternative -- refusing to remove symlinks inside a
 * sealed directory at all -- is worse.
 */
static int
target_clear(target_t *t)
{
	uint32_t want = t->saved & ~(uint32_t)BLOCKING_FLAGS;
	int slot, rc;

	if ((t->saved & BLOCKING_FLAGS) == 0)
		return (EX_HELPER_OK);
	slot = live_add(t->fd, t->saved, t->path);
	if (slot < 0) {
		errf("too many lifted seals at once");
		return (EX_HELPER_OPFAIL);
	}
	rc = t->fd >= 0 ? fchflags(t->fd, want) : lchflags(t->path, want);
	if (rc != 0) {
		errf("cannot lift flags on %s: %s", t->path, strerror(errno));
		live_forget(slot);
		return (EX_HELPER_OPFAIL);
	}
	t->live = slot;
	return (EX_HELPER_OK);
}

/*
 * Only mv restores a target's flags. `newpath` is non-NULL after a rename,
 * where the symlink fallback no longer finds the node under t->path.
 */
static int
target_restore(target_t *t, const char *newpath)
{
	int slot = t->live;

	t->live = -1;
	return (live_restore(slot, newpath));
}

/*
 * rm and trash let the node leave with its blocking bits already lifted:
 * there is nothing left to restore once it is gone. Called only after the
 * node has actually left the directory.
 */
static void
target_forget(target_t *t)
{
	live_forget(t->live);
	t->live = -1;
}

/* ---- recursive removal -------------------------------------------------- */

/*
 * Lift blocking flags on one leaf entry of `dfd`. Prefers the fd; falls back
 * to lchflags on the composed path for nodes that cannot be opened (symlinks,
 * sockets) with the nanosecond residual documented on target_clear().
 */
static int
leaf_clear(int dfd, const char *dpath, const char *name, const struct stat *st)
{
	uint32_t want = st->st_flags & ~(uint32_t)BLOCKING_FLAGS;
	int fd, rc = 0;
	char *p;

	if ((st->st_flags & BLOCKING_FLAGS) == 0)
		return (0);

	fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (fd >= 0) {
		struct stat now;

		if (fstat(fd, &now) != 0) {
			rc = -1;
		} else if (now.st_dev != st->st_dev ||
		    now.st_ino != st->st_ino) {
			errno = EIDRM;
			rc = -1;
		} else {
			rc = fchflags(fd, now.st_flags &
			    ~(uint32_t)BLOCKING_FLAGS);
		}
		close(fd);
	} else {
		p = join_path(dpath, name);
		rc = lchflags(p, want);
		free(p);
	}
	if (rc != 0)
		errf("cannot lift flags on %s/%s: %s", dpath, name,
		    strerror(errno));
	return (rc);
}

/*
 * Depth-first removal of the contents of `dfd`, whose own blocking flags the
 * caller has already lifted. Paths appear only in error text.
 *
 * Symlinks are unlinked as entries and never followed: descent happens only
 * through openat(O_NOFOLLOW|O_DIRECTORY), and an ELOOP from that call is proof
 * the entry became a symlink, which is then removed as a leaf.
 *
 * The entry names are read and the DIR closed before anything is deleted:
 * readdir over a directory being mutated may skip entries. Anything created
 * after the listing survives and surfaces as ENOTEMPTY from the caller's
 * rmdir, which is the honest answer to a concurrent writer.
 */
static int
rm_tree(int dfd, const char *dpath, dev_t dev, int depth)
{
	elist_t names;
	size_t i;
	int rc = 0;

	if (depth > MAX_DEPTH) {
		errf("tree deeper than %d levels below the target; refusing",
		    MAX_DEPTH);
		return (-1);
	}
	if (snapshot(dfd, dpath, &names) != 0)
		return (-1);

	for (i = 0; i < names.n && rc == 0; i++) {
		const char *name = names.v[i].name;
		struct stat st;
		int leaf = 0;

		if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
			if (errno == ENOENT)
				continue;	/* already gone */
			errf("cannot stat %s/%s: %s", dpath, name,
			    strerror(errno));
			rc = -1;
			break;
		}
		/* Checked before this entry is touched, so nothing on a foreign
		 * device is ever deleted. */
		if (st.st_dev != dev) {
			errf("%s/%s is on a different device; refusing to "
			    "delete across a mount point", dpath, name);
			rc = -1;
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			int cfd = openat(dfd, name, O_RDONLY | O_DIRECTORY |
			    O_NOFOLLOW | O_CLOEXEC);

			if (cfd < 0) {
				if (errno == ELOOP) {
					leaf = 1;	/* raced to a symlink */
				} else {
					errf("cannot open %s/%s: %s", dpath,
					    name, strerror(errno));
					rc = -1;
					break;
				}
			} else {
				struct stat cst;
				char *cpath;

				if (fstat(cfd, &cst) != 0) {
					errf("cannot stat %s/%s: %s", dpath,
					    name, strerror(errno));
					close(cfd);
					rc = -1;
					break;
				}
				if (cst.st_dev != dev ||
				    cst.st_ino != st.st_ino) {
					errf("%s/%s changed identity during "
					    "the walk; refusing", dpath, name);
					close(cfd);
					rc = -1;
					break;
				}
				/* Its own append-only/immutable bits block
				 * removal of its entries. */
				if ((cst.st_flags & BLOCKING_FLAGS) != 0 &&
				    fchflags(cfd, cst.st_flags &
				    ~(uint32_t)BLOCKING_FLAGS) != 0) {
					errf("cannot lift flags on %s/%s: %s",
					    dpath, name, strerror(errno));
					close(cfd);
					rc = -1;
					break;
				}
				cpath = join_path(dpath, name);
				rc = rm_tree(cfd, cpath, dev, depth + 1);
				free(cpath);
				close(cfd);	/* closed as we ascend */
				if (rc != 0)
					break;
				if (unlinkat(dfd, name, AT_REMOVEDIR) != 0) {
					errf("cannot remove %s/%s: %s", dpath,
					    name, strerror(errno));
					rc = -1;
					break;
				}
			}
		} else {
			leaf = 1;
		}

		if (leaf) {
			if (leaf_clear(dfd, dpath, name, &st) != 0) {
				rc = -1;
				break;
			}
			if (unlinkat(dfd, name, 0) != 0) {
				if (errno == ENOENT)
					continue;
				errf("cannot remove %s/%s: %s", dpath, name,
				    strerror(errno));
				rc = -1;
				break;
			}
		}
	}
	elist_free(&names);
	return (rc);
}

/* ---- argument parsing --------------------------------------------------- */

typedef struct {
	const char	*parent;
	const char	*parent_id;
	const char	*name;
	const char	*target_id;
	const char	*dest_parent;
	const char	*dest_parent_id;
	const char	*dest_name;
	const char	*src;
	const char	*src_id;
	const char	*dest;
	const char	*uid;
	const char	*gid;
	const char	*home;
	int		 recursive;
} opts_t;

static int
opt_str(const char *arg, const char *want, char **argv, int *ip, int argc,
    const char **slot)
{
	if (strcmp(arg, want) != 0)
		return (0);
	if (*ip + 1 >= argc) {
		errf("%s needs a value", want);
		return (-1);
	}
	if (*slot != NULL) {
		errf("%s given twice", want);
		return (-1);
	}
	*slot = argv[++(*ip)];
	return (1);
}

static int
parse_opts(int argc, char **argv, opts_t *o)
{
	int i;

	memset(o, 0, sizeof(*o));
	for (i = 2; i < argc; i++) {
		const char *a = argv[i];
		int r;

		if (strcmp(a, "--recursive") == 0) {
			o->recursive = 1;
			continue;
		}
#define TRY(flag, slot)							\
		r = opt_str(a, flag, argv, &i, argc, &o->slot);		\
		if (r < 0)						\
			return (-1);					\
		if (r > 0)						\
			continue;
		TRY("--parent", parent)
		TRY("--parent-id", parent_id)
		TRY("--name", name)
		TRY("--target-id", target_id)
		TRY("--dest-parent", dest_parent)
		TRY("--dest-parent-id", dest_parent_id)
		TRY("--dest-name", dest_name)
		TRY("--src", src)
		TRY("--src-id", src_id)
		TRY("--dest", dest)
		TRY("--uid", uid)
		TRY("--gid", gid)
		TRY("--home", home)
#undef TRY
		errf("unknown option %s", a);
		return (-1);
	}
	return (0);
}

static int
need(const char *v, const char *what)
{
	if (v != NULL)
		return (0);
	errf("%s is required", what);
	return (-1);
}

/*
 * Absolute paths only. A relative path would resolve against the process cwd,
 * which is the caller's and not something this binary should ever trust.
 */
static int
need_abs(const char *v, const char *what)
{
	if (need(v, what) != 0)
		return (-1);
	if (v[0] != '/') {
		errf("%s must be an absolute path", what);
		return (-1);
	}
	return (0);
}

/* A single path component: openat() must not be handed anything it could walk. */
static int
need_component(const char *v, const char *what)
{
	if (need(v, what) != 0)
		return (-1);
	if (v[0] == '\0' || strchr(v, '/') != NULL || strcmp(v, ".") == 0 ||
	    strcmp(v, "..") == 0) {
		errf("%s must be a single path component", what);
		return (-1);
	}
	/* Keeps the `binurl` line unambiguous without escaping it. */
	if (strpbrk(v, "\t\n") != NULL) {
		errf("%s must not contain a tab or a newline", what);
		return (-1);
	}
	return (0);
}

/*
 * Every id option must be PRESENT even when its value is "-". A missing one
 * would otherwise mean "verify nothing", so a caller that forgot to pass an id
 * would silently lose the identity gate rather than fail.
 */
static int
parse_ids(const char *s, nodeid_t *out, const char *what)
{
	if (need(s, what) != 0)
		return (-1);
	if (parse_id(s, out) != 0) {
		errf("%s is not a node identity", what);
		return (-1);
	}
	return (0);
}

/* ---- verb: rm ----------------------------------------------------------- */

static int
cmd_rm(int argc, char **argv)
{
	opts_t o;
	nodeid_t pid, tid;
	window_t w;
	target_t t;
	expect_t exp;
	int rc, status = EX_HELPER_OK, anomalies = 0;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.parent, "--parent") != 0 ||
	    need_component(o.name, "--name") != 0 ||
	    parse_ids(o.parent_id, &pid, "--parent-id") != 0 ||
	    parse_ids(o.target_id, &tid, "--target-id") != 0)
		return (EX_HELPER_USAGE);

	window_init(&w);
	target_init(&t);

	rc = window_open(&w, o.parent, &pid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	rc = target_open(&t, w.fd, o.parent, o.name, &tid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}

	/* Both identities are settled; only now is anything unsealed. */
	rc = window_clear(&w);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	rc = target_clear(&t);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}

	if (S_ISDIR(t.st.st_mode)) {
		if (o.recursive) {
			if (t.fd < 0) {
				errf("cannot open %s as a directory", t.path);
				status = EX_HELPER_OPFAIL;
				goto cleanup;
			}
			if (rm_tree(t.fd, t.path, t.st.st_dev, 0) != 0) {
				status = EX_HELPER_OPFAIL;
				goto cleanup;
			}
		}
		if (unlinkat(w.fd, o.name, AT_REMOVEDIR) != 0) {
			if (errno == ENOTEMPTY && !o.recursive)
				errf("%s is not empty and --recursive was not "
				    "given", t.path);
			else
				errf("cannot remove %s: %s", t.path,
				    strerror(errno));
			status = EX_HELPER_OPFAIL;
			goto cleanup;
		}
	} else {
		if (unlinkat(w.fd, o.name, 0) != 0) {
			int first = errno;

			/* Belt and braces: if the entry became a directory
			 * between the stat and here, retry the right way. */
			if ((first == EPERM || first == EISDIR) &&
			    unlinkat(w.fd, o.name, AT_REMOVEDIR) == 0) {
				/* removed */
			} else {
				errf("cannot remove %s: %s", t.path,
				    strerror(first));
				status = EX_HELPER_OPFAIL;
				goto cleanup;
			}
		}
	}

	/* The node is gone; its flags are not restored, by design. */
	target_forget(&t);

	if (snapshot(w.fd, w.path, &w.after) != 0) {
		/* The delta cannot be asserted, so it must not be claimed. */
		status = EX_HELPER_ANOMALY;
	} else {
		memset(&exp, 0, sizeof(exp));
		exp.gone = o.name;
		anomalies = diff_report(&w.before, &w.after, &exp);
		if (anomalies > 0)
			status = EX_HELPER_ANOMALY;
	}

cleanup:
	/* On a failed removal the node is still there, so its own blocking
	 * bits go back on; after a successful one target_forget() made this a
	 * no-op. Same alarm contract as a parent restore failure. */
	if (target_restore(&t, NULL) != 0)
		status = EX_HELPER_WINOPEN;
	if (window_restore(&w) != 0)
		status = EX_HELPER_WINOPEN;
	target_close(&t);
	window_close(&w);
	return (status);
}

/* ---- verb: mv ----------------------------------------------------------- */

static int
cmd_mv(int argc, char **argv)
{
	opts_t o;
	nodeid_t pid, dpid, tid;
	window_t sw, dw;
	target_t t;
	expect_t exp;
	char *newpath = NULL;
	int same_parent = 0;
	int rc, status = EX_HELPER_OK, anomalies = 0, moved = 0;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.parent, "--parent") != 0 ||
	    need_abs(o.dest_parent, "--dest-parent") != 0 ||
	    need_component(o.name, "--name") != 0 ||
	    need_component(o.dest_name, "--dest-name") != 0 ||
	    parse_ids(o.parent_id, &pid, "--parent-id") != 0 ||
	    parse_ids(o.dest_parent_id, &dpid, "--dest-parent-id") != 0 ||
	    parse_ids(o.target_id, &tid, "--target-id") != 0)
		return (EX_HELPER_USAGE);

	window_init(&sw);
	window_init(&dw);
	target_init(&t);

	rc = window_open(&sw, o.parent, &pid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	rc = window_open(&dw, o.dest_parent, &dpid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	/* Compared by identity, not by string: two names can reach the same
	 * directory, and clearing the same inode twice would leave the restore
	 * bookkeeping ambiguous. */
	same_parent = (sw.st.st_dev == dw.st.st_dev &&
	    sw.st.st_ino == dw.st.st_ino);
	if (!same_parent && sw.st.st_dev != dw.st.st_dev) {
		errf("cross-device move; copy+delete would drop flags and "
		    "xattrs -- refusing");
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

	rc = target_open(&t, sw.fd, o.parent, o.name, &tid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	newpath = join_path(o.dest_parent, o.dest_name);

	/* Every identity is settled before the first flag word moves. */
	rc = window_clear(&sw);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	if (!same_parent) {
		rc = window_clear(&dw);
		if (rc != EX_HELPER_OK) {
			status = rc;
			goto cleanup;
		}
	}
	rc = target_clear(&t);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}

	if (renameatx_np(sw.fd, o.name, dw.fd, o.dest_name, RENAME_EXCL) != 0) {
		if (errno == EEXIST)
			errf("%s already exists; refusing to clobber", newpath);
		else if (errno == EXDEV)
			errf("cross-device move; copy+delete would drop flags "
			    "and xattrs -- refusing");
		else
			errf("cannot move %s to %s: %s", t.path, newpath,
			    strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	moved = 1;
	live_repath(t.live, newpath);

	if (snapshot(sw.fd, sw.path, &sw.after) != 0) {
		status = EX_HELPER_ANOMALY;
	} else {
		memset(&exp, 0, sizeof(exp));
		exp.gone = o.name;
		if (same_parent) {
			exp.added = o.dest_name;
			exp.add_dev = t.st.st_dev;
			exp.add_ino = t.st.st_ino;
		}
		anomalies += diff_report(&sw.before, &sw.after, &exp);
	}
	if (!same_parent) {
		if (snapshot(dw.fd, dw.path, &dw.after) != 0) {
			status = EX_HELPER_ANOMALY;
		} else {
			memset(&exp, 0, sizeof(exp));
			exp.added = o.dest_name;
			exp.add_dev = t.st.st_dev;
			exp.add_ino = t.st.st_ino;
			anomalies += diff_report(&dw.before, &dw.after, &exp);
		}
	}
	if (anomalies > 0)
		status = EX_HELPER_ANOMALY;

cleanup:
	/* The node survives a move, so its own flags go back on. A failure here
	 * leaves a node unsealed just as a parent restore failure does, and
	 * gets the same alarm so the bash backstop re-seals it by path. */
	if (target_restore(&t, moved ? newpath : NULL) != 0)
		status = EX_HELPER_WINOPEN;
	if (window_restore(&dw) != 0)
		status = EX_HELPER_WINOPEN;
	if (window_restore(&sw) != 0)
		status = EX_HELPER_WINOPEN;
	free(newpath);
	target_close(&t);
	window_close(&dw);
	window_close(&sw);
	return (status);
}

/* ---- verb: trash -------------------------------------------------------- */

/*
 * Runs in the forked child, after the privilege drop has been verified. The
 * parent has not touched Foundation, so the Objective-C runtime is untouched
 * at fork time and this is its first use in the process image.
 *
 * The pipe protocol is internal to this binary: one tag byte, then a payload.
 * 'K' + the resulting item's filesystem path, or 'E' + a diagnostic.
 */
static void
trash_child(int wfd, const char *path)
{
	@autoreleasepool {
		NSString *p = [[NSFileManager defaultManager]
		    stringWithFileSystemRepresentation:path
		    length:strlen(path)];
		NSURL *src = [NSURL fileURLWithPath:p];
		NSURL *bin = nil;
		NSError *err = nil;
		BOOL ok;

		ok = [[NSFileManager defaultManager] trashItemAtURL:src
		    resultingItemURL:&bin error:&err];
		if (ok && bin != nil) {
			const char *out = [bin fileSystemRepresentation];
			size_t n = strlen(out);

			if (write(wfd, "K", 1) != 1)
				_exit(1);
			while (n > 0) {
				ssize_t w = write(wfd, out, n);

				if (w <= 0)
					_exit(1);
				out += w;
				n -= (size_t)w;
			}
			_exit(0);
		} else {
			const char *msg = err != nil ?
			    [[err localizedDescription] UTF8String] :
			    "trash service returned no destination";

			if (msg == NULL)
				msg = "trash service failed";
			(void)write(wfd, "E", 1);
			(void)write(wfd, msg, strlen(msg));
			_exit(1);
		}
	}
}

static int
cmd_trash(int argc, char **argv)
{
	opts_t o;
	nodeid_t pid, tid;
	window_t w;
	target_t t;
	expect_t exp;
	uid_t uid;
	gid_t gid;
	char *end;
	unsigned long v;
	int pfds[2] = { -1, -1 };
	pid_t child = -1;
	char buf[PATH_MAX + 64];
	size_t got = 0;
	uid_t prev_uid = 0;
	gid_t prev_gid = 0;
	int chowned = 0, trashed = 0;
	int rc, wstat = 0, status = EX_HELPER_OK, anomalies = 0;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.parent, "--parent") != 0 ||
	    need_component(o.name, "--name") != 0 ||
	    need_abs(o.home, "--home") != 0 ||
	    need(o.uid, "--uid") != 0 || need(o.gid, "--gid") != 0 ||
	    parse_ids(o.parent_id, &pid, "--parent-id") != 0 ||
	    parse_ids(o.target_id, &tid, "--target-id") != 0)
		return (EX_HELPER_USAGE);

	errno = 0;
	v = strtoul(o.uid, &end, 10);
	if (end == o.uid || *end != '\0' || errno != 0) {
		errf("--uid is not a number");
		return (EX_HELPER_USAGE);
	}
	uid = (uid_t)v;
	errno = 0;
	v = strtoul(o.gid, &end, 10);
	if (end == o.gid || *end != '\0' || errno != 0) {
		errf("--gid is not a number");
		return (EX_HELPER_USAGE);
	}
	gid = (gid_t)v;
	/* Trashing as root would fill root's bin, not the human's; the caller
	 * is required to know who is trashing. */
	if (uid == 0) {
		errf("refusing to trash as uid 0; the bin would be root's");
		return (EX_HELPER_USAGE);
	}

	window_init(&w);
	target_init(&t);

	rc = window_open(&w, o.parent, &pid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	rc = target_open(&t, w.fd, o.parent, o.name, &tid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}

	rc = window_clear(&w);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	rc = target_clear(&t);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}

	/* Content-tier nodes belong to the lock account; the bin entry must
	 * belong to whoever trashed it, or Put Back hands back a file they
	 * cannot read. */
	if (t.st.st_uid != uid) {
		int ok;

		prev_uid = t.st.st_uid;
		prev_gid = t.st.st_gid;
		if (t.fd >= 0)
			ok = (fchown(t.fd, uid, gid) == 0);
		else
			ok = (lchown(t.path, uid, gid) == 0);
		if (!ok) {
			errf("cannot give %s to uid %lu: %s", t.path,
			    (unsigned long)uid, strerror(errno));
			status = EX_HELPER_OPFAIL;
			goto cleanup;
		}
		chowned = 1;
	}

	if (pipe(pfds) != 0) {
		errf("cannot create pipe: %s", strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

	/* Nothing buffered may be inherited and re-emitted by the child. */
	fflush(stdout);
	fflush(stderr);

	child = fork();
	if (child < 0) {
		errf("cannot fork: %s", strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (child == 0) {
		gid_t g = gid;

		close(pfds[0]);
		/* stdout is the machine-line channel; anything Foundation
		 * decides to print must not land on it. */
		if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0)
			_exit(1);
		/* The lifted seals are the PARENT's to put back. The child is
		 * about to close those descriptors and drop privilege, so it
		 * must never run the restore handler on them. */
		memset(g_live, 0, sizeof(g_live));
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		/* Drop the root-opened descriptors before dropping privilege:
		 * a user-uid process must not inherit a capability on a
		 * directory it could not open for itself. */
		if (w.fd >= 0)
			close(w.fd);
		if (t.fd >= 0)
			close(t.fd);

		/* Order matters: supplementary groups, then gid, then uid.
		 * Any failure exits before Foundation is ever touched and
		 * before anything reaches the pipe. */
		if (setgroups(1, &g) != 0)
			_exit(1);
		if (setgid(gid) != 0)
			_exit(1);
		if (setuid(uid) != 0)
			_exit(1);
		if (getuid() != uid || geteuid() != uid ||
		    getgid() != gid || getegid() != gid)
			_exit(1);
		if (setenv("HOME", o.home, 1) != 0)
			_exit(1);

		trash_child(pfds[1], t.path);
		_exit(1);
	}

	close(pfds[1]);
	pfds[1] = -1;
	for (;;) {
		ssize_t n = read(pfds[0], buf + got, sizeof(buf) - 1 - got);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;
		got += (size_t)n;
		if (got >= sizeof(buf) - 1)
			break;
	}
	buf[got] = '\0';
	close(pfds[0]);
	pfds[0] = -1;

	while (waitpid(child, &wstat, 0) < 0) {
		if (errno != EINTR) {
			wstat = -1;
			break;
		}
	}
	child = -1;

	if (wstat != 0 || !(got > 0 && buf[0] == 'K')) {
		if (got > 0 && buf[0] == 'E')
			errf("trash service refused %s: %s", t.path, buf + 1);
		else
			errf("trash service failed on %s", t.path);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

	/* The node left with its blocking flags lifted, by design: it is the
	 * bin's now, and the record carries the seal state. */
	trashed = 1;
	target_forget(&t);

	/* --name is already free of tab and newline, and the service only adds
	 * a fixed bin directory and a collision suffix, so this cannot fire.
	 * If it ever does, a corrupt machine line is worse than no line. */
	if (strpbrk(buf + 1, "\t\n") != NULL) {
		errf("%s was trashed but its destination contains a control "
		    "character and cannot be reported", t.path);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	printf("binurl\t%s\n", buf + 1);

	if (snapshot(w.fd, w.path, &w.after) != 0) {
		status = EX_HELPER_ANOMALY;
	} else {
		memset(&exp, 0, sizeof(exp));
		exp.gone = o.name;
		anomalies = diff_report(&w.before, &w.after, &exp);
		if (anomalies > 0)
			status = EX_HELPER_ANOMALY;
	}

cleanup:
	if (pfds[0] >= 0)
		close(pfds[0]);
	if (pfds[1] >= 0)
		close(pfds[1]);
	if (child > 0)
		(void)waitpid(child, &wstat, 0);
	/* A trash that never happened must not leave the ownership handover
	 * behind: put the lock account back so the node reads exactly as its
	 * record says. Best effort -- a failure here surfaces as owner drift
	 * on the next verify, which is the alarm it deserves. */
	if (chowned && !trashed) {
		if (t.fd >= 0)
			(void)fchown(t.fd, prev_uid, prev_gid);
		else if (t.path != NULL)
			(void)lchown(t.path, prev_uid, prev_gid);
	}
	/* A failed trash leaves the node in place: its blocking bits go back
	 * on. After a successful one target_forget() made this a no-op. */
	if (target_restore(&t, NULL) != 0)
		status = EX_HELPER_WINOPEN;
	if (window_restore(&w) != 0)
		status = EX_HELPER_WINOPEN;
	target_close(&t);
	window_close(&w);
	return (status);
}

/* ---- verb: copy --------------------------------------------------------- */

static int
cmd_copy(int argc, char **argv)
{
	opts_t o;
	nodeid_t sid;
	struct stat st;
	int sfd = -1, dfd = -1, status = EX_HELPER_OK;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.src, "--src") != 0 || need_abs(o.dest, "--dest") != 0 ||
	    parse_ids(o.src_id, &sid, "--src-id") != 0)
		return (EX_HELPER_USAGE);

	sfd = open(o.src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (sfd < 0) {
		errf("cannot open %s: %s", o.src, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (fstat(sfd, &st) != 0) {
		errf("cannot stat %s: %s", o.src, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (check_id("source", o.src, &sid, &st, at_fd(sfd)) != 0) {
		status = EX_HELPER_IDENT;
		goto cleanup;
	}
	if (!S_ISREG(st.st_mode)) {
		errf("%s is not a regular file", o.src);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	/* The read from here on is from the verified fd, so a swap of the
	 * source name after this point copies nothing: this closes the logged
	 * source-side TOCTOU residual. */

	dfd = open(o.dest, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (dfd < 0) {
		if (errno == EEXIST)
			errf("%s already exists", o.dest);
		else
			errf("cannot create %s: %s", o.dest, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

	/*
	 * COPYFILE_STAT is deliberately absent. BSD `cp -p` preserves file
	 * flags, so a copy of a sealed source arrived immutable and even root's
	 * chown then failed with EPERM -- a live bug (repo history 66b5055).
	 * Data, xattrs and ACLs travel; mode, owner and the flag word are the
	 * caller's to set on the staged copy.
	 */
	if (fcopyfile(sfd, dfd, NULL,
	    COPYFILE_DATA | COPYFILE_XATTR | COPYFILE_ACL) != 0) {
		errf("cannot copy %s to %s: %s", o.src, o.dest,
		    strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

cleanup:
	if (sfd >= 0)
		close(sfd);
	if (dfd >= 0)
		close(dfd);
	return (status);
}

/* ---- verb: xattrs-from -------------------------------------------------- */

/*
 * Re-apply a sealed file's own extended attributes and ACLs to a staged
 * candidate whose CONTENT came from somewhere else. `locked edit` reads the
 * candidate as the invoker, with cat, which carries bytes and nothing else;
 * without this an edit would quietly strip attributes locked is holding the
 * file responsible for keeping. The candidate arrives with no attributes of
 * its own, so this is a re-application, never a merge -- nothing the
 * candidate brought is trusted or kept.
 *
 * COPYFILE_DATA and COPYFILE_STAT are both deliberately absent: the content
 * is exactly what the human approved in the diff, and mode, owner and the
 * flag word belong to the install step (see the cp -p hazard in cmd_copy).
 *
 * The source is pinned by identity, not by ownership -- an anchor-tier node
 * (~/.ssh/config) is legitimately owned by the invoker, so ownership says
 * nothing here, while the recorded identity says exactly which node this
 * has to be. The destination must be root-owned: it is the staging file the
 * caller just created, and anything else is not ours to write to.
 */
static int
cmd_xattrs_from(int argc, char **argv)
{
	opts_t o;
	nodeid_t sid;
	struct stat st;
	int sfd = -1, dfd = -1, status = EX_HELPER_OK;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.src, "--src") != 0 || need_abs(o.dest, "--dest") != 0 ||
	    parse_ids(o.src_id, &sid, "--src-id") != 0)
		return (EX_HELPER_USAGE);

	sfd = open(o.src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
	if (sfd < 0) {
		errf("cannot open %s: %s", o.src, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (fstat(sfd, &st) != 0) {
		errf("cannot stat %s: %s", o.src, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (check_id("source", o.src, &sid, &st, at_fd(sfd)) != 0) {
		status = EX_HELPER_IDENT;
		goto cleanup;
	}
	if (!S_ISREG(st.st_mode)) {
		errf("%s is not a regular file", o.src);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

	dfd = open(o.dest, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
	if (dfd < 0) {
		errf("cannot open %s: %s", o.dest, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (fstat(dfd, &st) != 0) {
		errf("cannot stat %s: %s", o.dest, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (!S_ISREG(st.st_mode)) {
		errf("%s is not a regular file", o.dest);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (st.st_uid != 0) {
		errf("%s is not root-owned; refusing", o.dest);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

	if (fcopyfile(sfd, dfd, NULL, COPYFILE_XATTR | COPYFILE_ACL) != 0) {
		errf("cannot carry attributes from %s to %s: %s", o.src,
		    o.dest, strerror(errno));
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

cleanup:
	if (sfd >= 0)
		close(sfd);
	if (dfd >= 0)
		close(dfd);
	return (status);
}

/* ---- verb: id ----------------------------------------------------------- */

/*
 * What the bash side's node_id() calls. Printing the identity from the same
 * code that later compares it is the point: the two sides cannot spell one
 * node differently. Mutates nothing and needs no root -- unprivileged
 * `locked status` reads identities too.
 */
static int
cmd_id(int argc, char **argv)
{
	struct stat st;
	voluuid_t vol;
	char buf[64];

	if (argc != 3) {
		errf("id takes exactly one path");
		return (EX_HELPER_USAGE);
	}
	/* Absolute like every other path this binary takes: one grammar, and
	 * nothing resolved against a cwd that is the caller's. */
	if (need_abs(argv[2], "<path>") != 0)
		return (EX_HELPER_USAGE);
	if (lstat(argv[2], &st) != 0) {
		errf("cannot stat %s: %s", argv[2], strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	vol.given = 0;
	(void)vol_uuid_at(AT_FDCWD, argv[2], &vol);
	if (vol.given)
		fmt_vol_id(buf, sizeof(buf), vol.u, st.st_ino);
	else
		fmt_id(buf, sizeof(buf), st.st_dev, st.st_ino);
	printf("%s\n", buf);
	return (EX_HELPER_OK);
}

/* ---- entry point -------------------------------------------------------- */

int
main(int argc, char **argv)
{
	struct sigaction sa;
	int status;

	/* O_CREAT modes below are exact; an inherited umask must not narrow
	 * them further or widen anything this process creates. */
	umask(077);

	/* A closed stdout must fail a write, not kill the process while a seal
	 * is lifted. */
	signal(SIGPIPE, SIG_IGN);

	/* Ctrl-C or a kill during the window re-seals before dying; the bash
	 * trap remains the outer backstop for anything this cannot catch. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	if (argc < 2) {
		usage();
		return (EX_HELPER_USAGE);
	}
	/* Dispatched before the root gate: `id` changes nothing, and the bash
	 * side's unprivileged verbs need it. */
	if (strcmp(argv[1], "id") == 0) {
		status = cmd_id(argc, argv);
		if (status == EX_HELPER_USAGE)
			usage();
		fflush(stdout);
		return (status);
	}

	if (geteuid() != 0) {
		errf("must run as root");
		return (EX_HELPER_USAGE);
	}

	if (strcmp(argv[1], "rm") == 0)
		status = cmd_rm(argc, argv);
	else if (strcmp(argv[1], "mv") == 0)
		status = cmd_mv(argc, argv);
	else if (strcmp(argv[1], "trash") == 0)
		status = cmd_trash(argc, argv);
	else if (strcmp(argv[1], "copy") == 0)
		status = cmd_copy(argc, argv);
	else if (strcmp(argv[1], "xattrs-from") == 0)
		status = cmd_xattrs_from(argc, argv);
	else {
		errf("unknown verb %s", argv[1]);
		usage();
		return (EX_HELPER_USAGE);
	}

	if (status == EX_HELPER_USAGE)
		usage();
	fflush(stdout);
	return (status);
}
