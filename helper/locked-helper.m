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
 * The same discipline carries the seal itself. `seal` and `unseal` change a
 * node's flag word, `install` puts an approved file in place of a sealed
 * one, and `copy-tree` copies a folder, each from a descriptor opened
 * O_NOFOLLOW (O_SYMLINK for a link) and checked on that descriptor: only a
 * directory, a regular file or a symlink, and only one owned by an account
 * the caller names. Every sealed node stays its owner's; the system flags
 * (schg, sappnd) bind the owner as well, and only root clears them. Root
 * never does more to an inode than the invoking user could do themselves,
 * and a second name for an inode someone else owns -- a hard link the user
 * planted after the plan was made -- is still owned by that someone else,
 * so it is refused.
 *
 * A file is never sealed as the inode it was. The kernel checks write
 * permission when a file is opened, not on each write, so a descriptor
 * opened for writing before the flag went on would keep writing after it.
 * `seal --swap` copies each regular file into root's staging, swaps the
 * copy in by one rename, and flags the copy: nothing of the invoker's ever
 * had it open. Every seal and install then lists the processes holding a
 * sealed file open for writing (the instant between the swap and the flag)
 * and names them. The fingerprint printed for each file is taken from the
 * copy before the swap, so a write in that instant shows as drift.
 *
 * The copy verbs also read as the invoker (--as) wherever the invoker owns
 * the path: the walk from "/" and the open of each node run under their
 * identity, so the kernel checks every folder on the way and the node's own
 * permission bits exactly as it would for them. Only a node owned by
 * another account in --owner (root, for its own staging) is opened by
 * root, from that node down, through the owner gate.
 *
 * A seal or an unseal is held to the plan's node count (--count): a first
 * pass counts, read-only, every node the verb would reach, and any other
 * number refuses before the first change; the passes that change nodes
 * stop at the first node past the count, before changing it.
 *
 * Exit codes are interface; the bash caller dispatches on them:
 *   0  ok
 *   2  identity refusal -- nothing was touched
 *   3  operation failed -- the window was restored, or a seal rolled back
 *   4  usage error or not root
 *   5  flag restore FAILED -- a window is LEFT OPEN; `window-open\t<path>`
 *      lines on stdout tell the bash backstop what to re-seal (for seal and
 *      unseal: the nodes a roll back could not restore, names escaped)
 *   6  operation completed but the parent's entry list changed in a way the
 *      operation does not account for; `anomaly` lines on stdout
 *   7  refused: a node is not a directory, file or symlink, is not owned
 *      by an account the caller named, cannot be reached as --as, or a
 *      walk's count differs from --count -- nothing changed, and whatever a
 *      seal had already changed was rolled back (a file already swapped
 *      stays the copy: the same bytes, owner, mode, times and attributes,
 *      a new inode)
 *   8  done, but a process holds a sealed file open for writing; `writer`
 *      lines on stdout name it (an anomaly in the same run is still on
 *      its lines)
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
 * window-open, writer `<pid> <program>`, sum `<sha256> <path below the
 * top, . for the top>`, and acl-absent: an unseal found no ACL entry as
 * --acl-remove names it, and left the ACL as it was), plus the one bare
 * line the `id` and `mount` verbs print. stderr carries one lowercase
 * prose line per error.
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
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/stdio.h>
#include <sys/wait.h>

#include <CommonCrypto/CommonDigest.h>
#include <copyfile.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libproc.h>
#include <limits.h>
#include <membership.h>
#include <pwd.h>
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
#define EX_HELPER_REFUSED  7
#define EX_HELPER_WRITER   8

/* The flags that block unlink/rename of a node, or of entries in a directory.
 * Nothing else in the flag word is ever touched: hidden, nodump, opaque and
 * the archived bit survive the window untouched because we restore the whole
 * saved word rather than re-deriving it. */
#define BLOCKING_FLAGS (SF_APPEND | UF_APPEND | SF_IMMUTABLE | UF_IMMUTABLE)

/* The flags a swapped-in copy carries over from the file it replaces. The
 * rest are the filesystem's to set (compressed, dataless, tracked) or the
 * seal's own. */
#define KEPT_FLAGS (UF_NODUMP | UF_HIDDEN)

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
"       locked-helper copy --src <path> --src-id <id|-> --owner <users>\n"
"                          --as <user> --dest <path>\n"
"       locked-helper copy-tree --src <dir> --src-id <id|-> --owner <users>\n"
"                               --as <user> --dest <dir>\n"
"                               --chown <user>:<group>\n"
"       locked-helper xattrs-from --src <path> --src-id <id|->\n"
"                                 --owner <users> --as <user>\n"
"                                 --dest <path>\n"
"       locked-helper seal|unseal --path <path> --id <id|-> --owner <users>\n"
"                                 --count <n>\n"
"                                 --flag <uchg|uappnd|schg|sappnd>\n"
"                                 [--recursive]\n"
"                                 [--swap --stage <dir>]          (seal)\n"
"                                 [--chown <user>:<group>] [--mode <octal>]\n"
"                                 [--acl-remove <user>:<rights>]  (unseal)\n"
"       locked-helper install --src <staged file> --parent <dir>\n"
"                             --parent-id <id|-> --name <entry>\n"
"                             (--target-id <id> --owner <users> | --new)\n"
"                             --chown <user>:<group> --mode <octal>\n"
"                             --flag <uchg|uappnd|schg|sappnd|none>\n"
"       locked-helper digest --src <path> --src-id <id|-> --owner <users>\n"
"                            --as <user> [--recursive]\n"
"       locked-helper id <path>\n"
"       locked-helper mount <path>\n",
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
	const char	*swapped;	/* entry this op swapped a copy into */
	ino_t		 swap_ino;	/* the copy's inode */
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
			if (exp->swapped != NULL &&
			    strcmp(exp->swapped, a->name) == 0 &&
			    a->ino == exp->swap_ino)
				continue;
			print_anomaly('~', a->name, a->dev, a->ino);
			found++;
		}
	}
	return (found);
}

/* ---- fingerprints and open writers -------------------------------------- */

/* sha256 of everything a held descriptor reads from offset 0, as hex. */
static int
sha256_fd(int fd, char out[65])
{
	CC_SHA256_CTX c;
	unsigned char md[CC_SHA256_DIGEST_LENGTH], buf[65536];
	off_t off = 0;
	ssize_t k;
	int i;

	CC_SHA256_Init(&c);
	while ((k = pread(fd, buf, sizeof(buf), off)) > 0) {
		CC_SHA256_Update(&c, buf, (CC_LONG)k);
		off += k;
	}
	if (k < 0)
		return (-1);
	CC_SHA256_Final(md, &c);
	for (i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
		snprintf(out + 2 * i, 3, "%02x", md[i]);
	return (0);
}

/* sum\t<sha256>\t<path below the top, escaped; . for the top> */
static void
print_sum(const char *hex, const char *rel)
{
	printf("sum\t%s\t", hex);
	print_escaped(rel[0] != '\0' ? rel : ".");
	fputc('\n', stdout);
}

typedef struct {
	dev_t	dev;
	ino_t	ino;
} inode_t;

typedef struct {
	inode_t	*v;
	size_t	 n;
	size_t	 cap;
} iset_t;

static void
iset_add(iset_t *s, dev_t dev, ino_t ino)
{
	if (s->n == s->cap) {
		size_t cap = s->cap ? s->cap * 2 : 16;
		inode_t *v = realloc(s->v, cap * sizeof(*v));

		if (v == NULL)
			fatal("out of memory");
		s->v = v;
		s->cap = cap;
	}
	s->v[s->n].dev = dev;
	s->v[s->n].ino = ino;
	s->n++;
}

static void
iset_free(iset_t *s)
{
	free(s->v);
	memset(s, 0, sizeof(*s));
}

/*
 * The open-writer check. The kernel asks for write permission when a file
 * is opened, never on each write, so a descriptor opened for writing
 * before a flag went on keeps writing after it. Every process's open files
 * are listed (libproc, as lsof does) and each descriptor of a file in `s`
 * opened for writing is named on a `writer` line: its pid and program.
 * This process's own descriptors do not count. Returns how many were
 * named, -1 when the process list cannot be read.
 *
 * Not seen, by design: a writable shared mapping whose descriptor was
 * closed, and a descriptor in flight in a socket message. The region data
 * cannot tell a shared mapping from a written private one, so a mapping
 * scan would raise false alarms. The fingerprint catches what either one
 * writes.
 */
static int
writer_scan(const iset_t *s)
{
	pid_t self = getpid(), *pids;
	struct proc_fdinfo *fds;
	struct vnode_fdinfowithpath vi;
	char name[64];
	size_t cap, nf, j, k;
	int n, i, sz, hits = 0;

	if (s->n == 0)
		return (0);
	n = proc_listallpids(NULL, 0);
	if (n <= 0) {
		errf("cannot list processes: %s", strerror(errno));
		return (-1);
	}
	cap = (size_t)n + 256;
	pids = xmalloc(cap * sizeof(*pids));
	n = proc_listallpids(pids, (int)(cap * sizeof(*pids)));
	if (n <= 0) {
		errf("cannot list processes: %s", strerror(errno));
		free(pids);
		return (-1);
	}
	for (i = 0; i < n; i++) {
		if (pids[i] == self || pids[i] == 0)
			continue;
		sz = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, NULL, 0);
		if (sz <= 0)
			continue;	/* gone since the list was read */
		sz += 64 * (int)sizeof(*fds);
		fds = xmalloc((size_t)sz);
		sz = proc_pidinfo(pids[i], PROC_PIDLISTFDS, 0, fds, sz);
		nf = sz > 0 ? (size_t)sz / sizeof(*fds) : 0;
		for (j = 0; j < nf; j++) {
			if (fds[j].proc_fdtype != PROX_FDTYPE_VNODE)
				continue;
			if (proc_pidfdinfo(pids[i], fds[j].proc_fd,
			    PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi)) !=
			    (int)sizeof(vi))
				continue;
			if ((vi.pfi.fi_openflags & FWRITE) == 0)
				continue;
			for (k = 0; k < s->n; k++)
				if ((uint32_t)vi.pvip.vip_vi.vi_stat.vst_dev ==
				    (uint32_t)s->v[k].dev &&
				    vi.pvip.vip_vi.vi_stat.vst_ino ==
				    (uint64_t)s->v[k].ino)
					break;
			if (k == s->n)
				continue;
			if (proc_name(pids[i], name, sizeof(name)) <= 0)
				strlcpy(name, "?", sizeof(name));
			printf("writer\t%d\t", (int)pids[i]);
			print_escaped(name);
			fputc('\n', stdout);
			hits++;
		}
		free(fds);
	}
	free(pids);
	return (hits);
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
	const char	*path;
	const char	*id;
	const char	*owner;
	const char	*flag;
	const char	*chown;
	const char	*mode;
	const char	*as;
	const char	*count;
	const char	*acl_remove;
	const char	*stage;
	int		 recursive;
	int		 swap;
	int		 new_node;
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
		if (strcmp(a, "--swap") == 0) {
			o->swap = 1;
			continue;
		}
		if (strcmp(a, "--new") == 0) {
			o->new_node = 1;
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
		TRY("--path", path)
		TRY("--id", id)
		TRY("--owner", owner)
		TRY("--flag", flag)
		TRY("--chown", chown)
		TRY("--mode", mode)
		TRY("--as", as)
		TRY("--count", count)
		TRY("--acl-remove", acl_remove)
		TRY("--stage", stage)
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

/* ---- accounts, modes and flag words ------------------------------------- */

/* A user by name or by number, the way chown(8) takes one. */
static int
parse_user(const char *s, uid_t *out)
{
	struct passwd *pw;
	char *end;
	unsigned long v;

	if (s[0] == '\0')
		return (-1);
	if (strspn(s, "0123456789") == strlen(s)) {
		errno = 0;
		v = strtoul(s, &end, 10);
		if (errno != 0 || *end != '\0' || v > UINT32_MAX)
			return (-1);
		*out = (uid_t)v;
		return (0);
	}
	pw = getpwnam(s);
	if (pw == NULL)
		return (-1);
	*out = pw->pw_uid;
	return (0);
}

static int
parse_group(const char *s, gid_t *out)
{
	struct group *gr;
	char *end;
	unsigned long v;

	if (s[0] == '\0')
		return (-1);
	if (strspn(s, "0123456789") == strlen(s)) {
		errno = 0;
		v = strtoul(s, &end, 10);
		if (errno != 0 || *end != '\0' || v > UINT32_MAX)
			return (-1);
		*out = (gid_t)v;
		return (0);
	}
	gr = getgrnam(s);
	if (gr == NULL)
		return (-1);
	*out = gr->gr_gid;
	return (0);
}

#define MAX_OWNERS 4

/* The accounts a node may be owned by for a verb to act on it. */
typedef struct {
	uid_t	v[MAX_OWNERS];
	int	n;
} owners_t;

/* --owner: one account, or a comma list of up to four. */
static int
parse_owners(const char *s, owners_t *o)
{
	char buf[256], *p, *tok;

	o->n = 0;
	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return (-1);
	p = buf;
	while ((tok = strsep(&p, ",")) != NULL) {
		if (o->n == MAX_OWNERS || parse_user(tok, &o->v[o->n]) != 0)
			return (-1);
		o->n++;
	}
	return (o->n > 0 ? 0 : -1);
}

/* --chown: <user>:<group>, names or numbers. */
static int
parse_chown(const char *s, uid_t *u, gid_t *g)
{
	char buf[256], *colon;

	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return (-1);
	colon = strchr(buf, ':');
	if (colon == NULL)
		return (-1);
	*colon = '\0';
	if (parse_user(buf, u) != 0 || parse_group(colon + 1, g) != 0)
		return (-1);
	return (0);
}

/* --mode: octal permission bits, as stat -f '%OLp' prints them. */
static int
parse_mode(const char *s, mode_t *m)
{
	char *end;
	unsigned long v;

	if (s[0] == '\0' || strspn(s, "01234567") != strlen(s))
		return (-1);
	errno = 0;
	v = strtoul(s, &end, 8);
	if (errno != 0 || *end != '\0' || v > 07777)
		return (-1);
	*m = (mode_t)v;
	return (0);
}

/* --flag: the one flag a seal sets or an unseal clears. */
static int
parse_flag(const char *s, uint32_t *bit)
{
	if (strcmp(s, "uchg") == 0)
		*bit = UF_IMMUTABLE;
	else if (strcmp(s, "uappnd") == 0)
		*bit = UF_APPEND;
	else if (strcmp(s, "schg") == 0)
		*bit = SF_IMMUTABLE;
	else if (strcmp(s, "sappnd") == 0)
		*bit = SF_APPEND;
	else
		return (-1);
	return (0);
}

/* An account for prose: its name, or its number when it has none. */
static void
user_name(uid_t u, char *buf, size_t n)
{
	struct passwd *pw = getpwuid(u);

	if (pw != NULL)
		snprintf(buf, n, "%s", pw->pw_name);
	else
		snprintf(buf, n, "uid %lu", (unsigned long)u);
}

/* --count: how many nodes the plan names, the top included. */
static int
parse_count(const char *s, size_t *out)
{
	char *end;
	unsigned long long v;

	if (s[0] == '\0' || strspn(s, "0123456789") != strlen(s))
		return (-1);
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno != 0 || *end != '\0' || v == 0)
		return (-1);
	*out = (size_t)v;
	return (0);
}

/*
 * The one ACL entry a placement seal of locked 0.16 and earlier gave the
 * invoker, which the one-shot conversion to system flags takes off again:
 * an allow naming one account by its uuid, with exactly the listed rights
 * and no inherit flag. The rights are the ones that seal granted, by the
 * names ls -le prints them under; any other right is refused.
 * TODO(0.18.0): remove with the conversion.
 */
typedef struct {
	int			 op;	/* 0 none, -1 remove (unseal) */
	uid_t			 uid;
	uuid_t			 who;
	acl_permset_mask_t	 rights;
	int			 absent; /* unseal: no such entry was there */
} aclspec_t;

static const struct {
	const char	*name;
	acl_perm_t	 perm;
} acl_rights[] = {
	{ "list",		ACL_LIST_DIRECTORY },
	{ "add_file",		ACL_ADD_FILE },
	{ "search",		ACL_SEARCH },
	{ "add_subdirectory",	ACL_ADD_SUBDIRECTORY },
	{ "readattr",		ACL_READ_ATTRIBUTES },
	{ "readextattr",	ACL_READ_EXTATTRIBUTES },
	{ "readsecurity",	ACL_READ_SECURITY },
};

/* The inherit flags an entry of ours never carries. */
static const acl_flag_t acl_inherit[] = {
	ACL_ENTRY_INHERITED, ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT,
	ACL_ENTRY_LIMIT_INHERIT, ACL_ENTRY_ONLY_INHERIT,
};

#define NITEMS(a) (sizeof(a) / sizeof((a)[0]))

/* --acl-add, --acl-remove: <user>:<right>[,<right>...]. */
static int
parse_acl(const char *s, const char *what, aclspec_t *a)
{
	char buf[512], *colon, *p, *tok;
	size_t i;

	a->rights = 0;
	if (strlcpy(buf, s, sizeof(buf)) >= sizeof(buf) ||
	    (colon = strchr(buf, ':')) == NULL || colon[1] == '\0') {
		errf("%s must be <user>:<right>[,<right>...]", what);
		return (-1);
	}
	*colon = '\0';
	if (parse_user(buf, &a->uid) != 0) {
		errf("%s names no account: %s", what, buf);
		return (-1);
	}
	if (mbr_uid_to_uuid(a->uid, a->who) != 0) {
		errf("%s names an account with no uuid: %s", what, buf);
		return (-1);
	}
	p = colon + 1;
	while ((tok = strsep(&p, ",")) != NULL) {
		for (i = 0; i < NITEMS(acl_rights); i++)
			if (strcmp(tok, acl_rights[i].name) == 0)
				break;
		if (i == NITEMS(acl_rights)) {
			errf("%s names a right a placement seal does not grant: "
			    "'%s'", what, tok);
			return (-1);
		}
		a->rights |= (acl_permset_mask_t)acl_rights[i].perm;
	}
	return (0);
}

/* ---- reading as the invoker --------------------------------------------- */

/*
 * The account a copy reads as. The owner gate is this binary checking one
 * fact on one descriptor; reading as the invoker has the kernel check every
 * folder on the way and the node's own permission bits, so a file of
 * theirs inside a folder they cannot enter is refused rather than read by
 * root. The lock account cannot stand in for itself the same way: it is a
 * hidden account outside the invoker's groups, and their home is closed to
 * it. So a node owned by another account in --owner is opened by root,
 * from that node down, through the gate. Only the walk and the opens
 * change identity; the copying runs as root, on descriptors already held.
 */
typedef struct {
	int		 other;		/* --as is not this process's account */
	uid_t		 uid;
	gid_t		 gid;
	char		 name[256];
	const owners_t	*owners;
} reader_t;

static int	g_as_reader;	/* 1 while the process holds --as's identity */
static uid_t	g_self_uid;
static gid_t	g_self_gid;
static char	g_self_name[256];

/* --as: an account by name or number, with its primary group. */
static int
parse_reader(const char *s, const owners_t *owners, reader_t *r)
{
	struct passwd *pw;
	uid_t u;

	memset(r, 0, sizeof(*r));
	if (parse_user(s, &u) != 0 || (pw = getpwuid(u)) == NULL ||
	    strlcpy(r->name, pw->pw_name, sizeof(r->name)) >= sizeof(r->name))
		return (-1);
	r->uid = u;
	r->gid = pw->pw_gid;
	r->owners = owners;
	r->other = u != g_self_uid;
	if (!r->other)
		return (0);
	pw = getpwuid(g_self_uid);
	if (pw == NULL || strlcpy(g_self_name, pw->pw_name,
	    sizeof(g_self_name)) >= sizeof(g_self_name))
		return (-1);
	return (0);
}

/* A node owned by another account the caller named is root's to open. */
static int
owned_by_other(const reader_t *r, uid_t u)
{
	int i;

	if (u == r->uid)
		return (0);
	for (i = 0; i < r->owners->n; i++)
		if (u == r->owners->v[i])
			return (1);
	return (0);
}

/*
 * Groups, then group, then user; back in the reverse order. The real and
 * saved ids stay root's, so the invoker's own processes cannot signal this
 * one meanwhile. A failure either way ends the process before anything
 * else is opened, read or written.
 */
static void
become_reader(const reader_t *r)
{
	if (r == NULL || !r->other || g_as_reader)
		return;
	if (initgroups(r->name, (int)r->gid) != 0 || setegid(r->gid) != 0 ||
	    seteuid(r->uid) != 0)
		fatal("cannot take on the identity a copy reads as");
	g_as_reader = 1;
}

static void
become_self(void)
{
	if (!g_as_reader)
		return;
	if (seteuid(g_self_uid) != 0 || setegid(g_self_gid) != 0 ||
	    initgroups(g_self_name, (int)g_self_gid) != 0)
		fatal("cannot take back this process's own identity");
	g_as_reader = 0;
}

/* ---- reaching a node by descriptor -------------------------------------- */

/* How many symlinks one walk may follow. /var, /tmp and /etc take one each;
 * a longer chain is refused. */
#define MAX_LINK_HOPS 8

/* A directory only root can change: root's, and writable by neither its
 * group nor others. */
static int
root_only(int fd)
{
	struct stat st;

	return (fstat(fd, &st) == 0 && st.st_uid == 0 &&
	    (st.st_mode & (S_IWGRP | S_IWOTH)) == 0);
}

/*
 * The walk met a symlink, `name` in the directory `fd`. It follows it only
 * where root alone decides what it points at: the link is root's, and every
 * directory from "/" down to it is root_only (`trusted`), so no other
 * account could have placed the link, changed it, or moved the folder that
 * holds it onto the path. That is how /var, /tmp and /etc reach /private.
 * Any other link is the refusal it always was. The target must be a plain
 * path, with no empty, "." or ".." component. 0 with the target in `out`,
 * -2 for a refusal, -1 for any other failure.
 */
static int
link_target(int fd, const char *name, int trusted, const char *path,
    char *out, size_t outsz)
{
	struct stat st;
	ssize_t n;
	const char *c, *end;
	size_t len;

	if (fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
		errf("cannot read a symlink on the path (%s): %s",
		    strerror(errno), path);
		return (-1);
	}
	if (!S_ISLNK(st.st_mode) || st.st_uid != 0 || !trusted) {
		errf("refusing, a directory on the path is a symlink or not a "
		    "directory: %s", path);
		return (-2);
	}
	n = readlinkat(fd, name, out, outsz);
	if (n < 0) {
		errf("cannot read a symlink on the path (%s): %s",
		    strerror(errno), path);
		return (-1);
	}
	if ((size_t)n >= outsz) {
		errf("path too long: %s", path);
		return (-1);
	}
	out[n] = '\0';
	c = out[0] == '/' ? out + 1 : out;
	for (;;) {
		end = strchr(c, '/');
		len = end != NULL ? (size_t)(end - c) : strlen(c);
		if (len == 0 || (len == 1 && c[0] == '.') ||
		    (len == 2 && c[0] == '.' && c[1] == '.')) {
			errf("refusing, a symlink on the path does not point at "
			    "a plain path: %s", path);
			return (-2);
		}
		if (end == NULL)
			return (0);
		c = end + 1;
	}
}

/*
 * The directory that holds the last component of an absolute path, reached
 * one component at a time from "/" with O_NOFOLLOW, so no symlink anywhere on
 * the way can redirect the walk unless root alone controls it (link_target:
 * /var and its kind). The callers pass canonical paths (the bash side
 * resolves the parent with readlink -f), so any other symlink met here means
 * the path changed after it was resolved, and that is a refusal: -2, where
 * any other failure is -1. On success *leaf points into `buf`.
 * O_SEARCH: a walk needs to pass through each directory, never to read one.
 *
 * With a reader and *inr set, the walk runs as the reader until it meets a
 * directory another account in --owner owns, and as this process from that
 * one on; *inr says which it ended as. A folder the reader cannot enter is
 * a refusal. The callers take back their own identity afterwards.
 */
static int
open_parent(const char *path, char *buf, size_t bufsz, const char **leaf,
    const reader_t *r, int *inr)
{
	struct stat st, got;
	char *p, *slash, tgt[PATH_MAX], tmp[PATH_MAX];
	int fd, nfd, e, reading, handed, trusted, hops = 0, rc;

	if (strlcpy(buf, path, bufsz) >= bufsz) {
		errf("path too long: %s", path);
		return (-1);
	}
	reading = r != NULL && *inr;
	if (reading)
		become_reader(r);
	fd = open("/", O_SEARCH | O_CLOEXEC);
	if (fd < 0) {
		errf("cannot open /: %s", strerror(errno));
		return (-1);
	}
	trusted = root_only(fd);
	p = buf + 1;
	for (;;) {
		slash = strchr(p, '/');
		if (slash != NULL)
			*slash = '\0';
		if (p[0] == '\0' || strcmp(p, ".") == 0 || strcmp(p, "..") == 0) {
			errf("refusing a path that is not canonical: %s", path);
			close(fd);
			return (-2);
		}
		if (slash == NULL)
			break;
		handed = 0;
		if (reading) {
			if (fstatat(fd, p, &st, AT_SYMLINK_NOFOLLOW) != 0) {
				e = errno;
				close(fd);
				goto failed;
			}
			if (owned_by_other(r, st.st_uid)) {
				become_self();
				reading = 0;
				handed = 1;
			}
		}
		nfd = openat(fd, p, O_SEARCH | O_NOFOLLOW | O_CLOEXEC);
		e = errno;
		if (nfd < 0 && (e == ELOOP || e == ENOTDIR)) {
			/* A symlink (O_SEARCH reports one as ENOTDIR as often
			 * as ELOOP; link_target asks the node itself): followed
			 * only as link_target allows, by putting its target in
			 * its place and walking on. */
			if (++hops > MAX_LINK_HOPS) {
				errf("refusing, the path goes through more than "
				    "%d symlinks: %s", MAX_LINK_HOPS, path);
				close(fd);
				return (-2);
			}
			rc = link_target(fd, p, trusted, path, tgt, sizeof(tgt));
			if (rc == 0 && ((size_t)snprintf(tmp, sizeof(tmp), "%s/%s",
			    tgt, slash + 1) >= sizeof(tmp) ||
			    strlcpy(buf, tmp, bufsz) >= bufsz)) {
				errf("path too long: %s", path);
				rc = -1;
			}
			if (rc != 0) {
				close(fd);
				return (rc);
			}
			p = buf;
			if (buf[0] == '/') {
				close(fd);
				fd = open("/", O_SEARCH | O_CLOEXEC);
				if (fd < 0) {
					errf("cannot open /: %s", strerror(errno));
					return (-1);
				}
				trusted = root_only(fd);
				p = buf + 1;
			}
			continue;
		}
		close(fd);
		if (nfd < 0)
			goto failed;
		trusted = trusted && root_only(nfd);
		/* Root opens from here on what the stat said another account
		 * owns, so it must still be that node. */
		if (handed && (fstat(nfd, &got) != 0 ||
		    got.st_ino != st.st_ino || got.st_dev != st.st_dev ||
		    got.st_uid != st.st_uid)) {
			errf("refusing, a directory on the path changed while it "
			    "was reached: %s", path);
			close(nfd);
			return (-2);
		}
		fd = nfd;
		p = slash + 1;
	}
	if (r != NULL)
		*inr = reading;
	*leaf = p;
	return (fd);

failed:
	if (e == ELOOP || e == ENOTDIR) {
		errf("refusing, a directory on the path is a symlink or not a "
		    "directory: %s", path);
		return (-2);
	}
	if (reading && e == EACCES) {
		errf("refusing, %s cannot enter a directory on the path: %s",
		    r->name, path);
		return (-2);
	}
	errf("cannot open a directory on the path (%s): %s", strerror(e),
	    path);
	return (-1);
}

/* A node held by descriptor, with what fstat said of that descriptor. */
typedef struct {
	int		fd;
	struct stat	st;
} node_t;

static const char *
kind_of(mode_t m)
{
	if (S_ISFIFO(m))
		return ("fifo");
	if (S_ISSOCK(m))
		return ("socket");
	if (S_ISCHR(m))
		return ("character device");
	if (S_ISBLK(m))
		return ("block device");
	return ("node of an unknown type");
}

/*
 * Open the entry `name` of the held directory `pfd` as the node it is: a
 * directory O_DIRECTORY|O_NOFOLLOW, a file or a symlink O_SYMLINK, which
 * opens a link itself and never what it points at. Anything else -- a fifo,
 * a socket, a device -- is refused before it is opened. The descriptor is
 * authoritative from here, so its own fstat must agree with the entry's: a
 * swap between the two calls is refused, never followed.
 *
 * With a reader and *inr set, the stat and the open run as the reader,
 * unless the stat finds the node another account in --owner owns: then
 * this process opens it, and *inr goes to 0 for everything below it.
 */
static int
node_at_as(int pfd, const char *name, const char *path, node_t *n,
    const reader_t *r, int *inr)
{
	struct stat st0;
	int flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC;
	int reading = r != NULL && *inr;

	n->fd = -1;
	if (reading)
		become_reader(r);
	if (fstatat(pfd, name, &st0, AT_SYMLINK_NOFOLLOW) != 0) {
		if (reading && errno == EACCES) {
			errf("refusing, %s cannot reach it: %s", r->name, path);
			return (EX_HELPER_REFUSED);
		}
		errf("cannot stat (%s): %s", strerror(errno), path);
		return (EX_HELPER_OPFAIL);
	}
	if (!S_ISDIR(st0.st_mode) && !S_ISREG(st0.st_mode) &&
	    !S_ISLNK(st0.st_mode)) {
		errf("refusing, a %s is not a file, directory or symlink: %s",
		    kind_of(st0.st_mode), path);
		return (EX_HELPER_REFUSED);
	}
	if (reading && owned_by_other(r, st0.st_uid)) {
		become_self();
		reading = 0;
		*inr = 0;
	}
	flags |= S_ISDIR(st0.st_mode) ? (O_DIRECTORY | O_NOFOLLOW) : O_SYMLINK;
	n->fd = openat(pfd, name, flags);
	if (n->fd < 0) {
		if (errno == ELOOP || errno == ENOTDIR) {
			errf("refusing, it changed type between stat and "
			    "open: %s", path);
			return (EX_HELPER_REFUSED);
		}
		if (reading && errno == EACCES) {
			errf("refusing, %s may not open it: %s", r->name, path);
			return (EX_HELPER_REFUSED);
		}
		errf("cannot open (%s): %s", strerror(errno), path);
		return (EX_HELPER_OPFAIL);
	}
	if (fstat(n->fd, &n->st) != 0) {
		errf("cannot stat (%s): %s", strerror(errno), path);
		close(n->fd);
		n->fd = -1;
		return (EX_HELPER_OPFAIL);
	}
	if ((n->st.st_mode & S_IFMT) != (st0.st_mode & S_IFMT) ||
	    n->st.st_ino != st0.st_ino || n->st.st_dev != st0.st_dev ||
	    n->st.st_uid != st0.st_uid) {
		errf("refusing, it changed between stat and open: %s", path);
		close(n->fd);
		n->fd = -1;
		return (EX_HELPER_REFUSED);
	}
	return (EX_HELPER_OK);
}

static int
node_at(int pfd, const char *name, const char *path, node_t *n)
{
	return (node_at_as(pfd, name, path, n, NULL, NULL));
}

/*
 * The owner gate. A node's owner says whose it is: a second name for a file
 * the invoker owns gives them nothing new, while a hard link to a root-owned
 * file is still root's, whatever directory it was linked into. So the gate
 * is the owner, never the link count, and it is asked of the descriptor the
 * verb then acts on.
 */
static int
gate_owner(const struct stat *st, const char *path, const owners_t *ok)
{
	char got[64], one[64], want[300];
	int i;

	for (i = 0; i < ok->n; i++)
		if (st->st_uid == ok->v[i])
			return (EX_HELPER_OK);
	user_name(st->st_uid, got, sizeof(got));
	want[0] = '\0';
	for (i = 0; i < ok->n; i++) {
		user_name(ok->v[i], one, sizeof(one));
		if (i > 0)
			strlcat(want, " or ", sizeof(want));
		strlcat(want, one, sizeof(want));
	}
	errf("refusing, owned by %s and not by %s: %s", got, want, path);
	return (EX_HELPER_REFUSED);
}

/*
 * `setid` is for a seal: locked does not seal a set-user-id or
 * set-group-id file. That is policy, kept from the time a seal gave every
 * node to another account; a sealed file stays its owner's now.
 */
static int
gate(const node_t *n, const char *path, const owners_t *ok, int setid)
{
	if (gate_owner(&n->st, path, ok) != EX_HELPER_OK)
		return (EX_HELPER_REFUSED);
	if (setid && S_ISREG(n->st.st_mode) &&
	    (n->st.st_mode & (S_ISUID | S_ISGID)) != 0) {
		errf("refusing, a set-user-id or set-group-id file would run "
		    "as its new owner once sealed: %s", path);
		return (EX_HELPER_REFUSED);
	}
	return (EX_HELPER_OK);
}

/* <rel>/<name>, or <name> when rel is the top itself (""). */
static char *
rel_join(const char *rel, const char *name)
{
	return (rel[0] == '\0' ? xstrdup(name) : join_path(rel, name));
}

#ifdef LOCKED_HELPER_TEST
/*
 * TEST BUILDS ONLY. Compiled in by -DLOCKED_HELPER_TEST, which neither the
 * nix module nor the README's build line passes; the harness builds this
 * variant separately and checks that the release build holds none of it.
 * LOCKED_HELPER_TEST_PAUSE=<verb>:<fifo> makes that verb wait, before it
 * opens anything, until a byte arrives on the fifo: the moment between
 * locked's plan and the helper's apply, held open so a test can plant a
 * node there deterministically. seal-walk and unseal-walk hold the moment
 * after the count pass instead. A test build also skips the root gate, so
 * the gates below can be exercised as an ordinary user, with that user's
 * own rights.
 */
static void
test_pause(const char *verb)
{
	const char *v = getenv("LOCKED_HELPER_TEST_PAUSE");
	size_t n = strlen(verb);
	char c;
	int fd;

	if (v == NULL || strncmp(v, verb, n) != 0 || v[n] != ':')
		return;
	fd = open(v + n + 1, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	(void)read(fd, &c, 1);
	close(fd);
}
#define TEST_PAUSE(verb)	test_pause(verb)
#else
#define TEST_PAUSE(verb)	((void)0)
#endif

/* ---- seal and unseal ---------------------------------------------------- */

/*
 * What a node was before this run changed it. A seal or an unseal is all or
 * nothing: on any refusal or failure every journaled node is put back, so a
 * refused run leaves the tree exactly as it found it.
 */
typedef struct {
	char		*rel;	/* path below the top, "" for the top itself */
	mode_t		 type;	/* S_IFDIR, S_IFREG or S_IFLNK */
	ino_t		 ino;
	uid_t		 uid;
	gid_t		 gid;
	mode_t		 mode;	/* permission bits */
	uint32_t	 flags;
	int		 acl_kept;	/* this run changed the node's ACL */
	acl_t		 acl;	/* what it held then; NULL for none */
} jent_t;

typedef struct {
	int		 sealing;	/* 1 seal, 0 unseal */
	const owners_t	*owners;
	uint32_t	 flag;
	int		 chown;
	uid_t		 uid;
	gid_t		 gid;
	int		 has_mode;
	mode_t		 mode;
	int		 recursive;
	aclspec_t	 acl;		/* --acl-remove */
	int		 swap;		/* --swap: each file sealed is a copy */
	int		 sfd;		/* --stage, held */
	unsigned	 seq;		/* names in staging */
	elist_t		 staged;	/* originals parked in staging */
	iset_t		 flagged;	/* regular files this seal flagged */
	int		 anomalies;	/* entry changes in a swap window */
	size_t		 plan;		/* --count */
	size_t		 seen;		/* nodes this pass has reached */
	dev_t		 dev;
	int		 topfd;
	const char	*top;
	jent_t		*jv;
	size_t		 jn;
	size_t		 jcap;
} tree_t;

static const char *
nodes_word(size_t n)
{
	return (n == 1 ? "node" : "nodes");
}

/*
 * The count guard, in the passes that change nodes. No pass reaches more
 * nodes than the plan names: a walk that strays below a node it was not
 * asked to walk stops at the first node past the count, before that node
 * is changed, and the roll back puts back what the pass already changed.
 */
static int
visit(tree_t *t, const char *path)
{
	if (++t->seen <= t->plan)
		return (EX_HELPER_OK);
	errf("refusing, the plan names %zu %s and the walk reached more: %s",
	    t->plan, nodes_word(t->plan), path);
	return (EX_HELPER_REFUSED);
}

/* At the end of a pass: it reached exactly the plan's nodes. */
static int
count_matches(const tree_t *t, const char *reached)
{
	if (t->seen == t->plan)
		return (EX_HELPER_OK);
	errf("refusing, the plan names %zu %s and %s %zu: %s", t->plan,
	    nodes_word(t->plan), reached, t->seen, t->top);
	return (EX_HELPER_REFUSED);
}

static void
journal_push(tree_t *t, const char *rel, const struct stat *st)
{
	jent_t *e;

	if (t->jn == t->jcap) {
		size_t cap = t->jcap ? t->jcap * 2 : 64;
		jent_t *v = realloc(t->jv, cap * sizeof(*v));

		if (v == NULL)
			fatal("out of memory");
		t->jv = v;
		t->jcap = cap;
	}
	e = &t->jv[t->jn++];
	e->rel = xstrdup(rel);
	e->type = st->st_mode & S_IFMT;
	e->ino = st->st_ino;
	e->uid = st->st_uid;
	e->gid = st->st_gid;
	e->mode = st->st_mode & 07777;
	e->flags = st->st_flags;
	e->acl_kept = 0;
	e->acl = NULL;
}

/* True when this run already changed that inode: a second name inside the
 * same tree for a file the walk has sealed, met again further on. */
static int
journal_has(const tree_t *t, ino_t ino)
{
	size_t i;

	for (i = 0; i < t->jn; i++)
		if (t->jv[i].ino == ino)
			return (1);
	return (0);
}

static void
journal_free(tree_t *t)
{
	size_t i;

	for (i = 0; i < t->jn; i++) {
		free(t->jv[i].rel);
		if (t->jv[i].acl != NULL)
			acl_free(t->jv[i].acl);
	}
	free(t->jv);
	t->jv = NULL;
	t->jn = 0;
	t->jcap = 0;
}

/* The ACL a held node carries, or NULL for none. */
static int
acl_read(int fd, const char *path, acl_t *out)
{
	*out = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (*out != NULL || errno == ENOENT)
		return (0);
	errf("cannot read the ACL of it (%s): %s", strerror(errno), path);
	return (-1);
}

/* The entry is the one the spec names: an allow for that account, with
 * exactly those rights and no inherit flag. */
static int
acl_is_ours(acl_entry_t e, const aclspec_t *a)
{
	acl_tag_t tag;
	acl_permset_mask_t m;
	acl_flagset_t fs;
	void *q;
	size_t i;
	int same;

	if (acl_get_tag_type(e, &tag) != 0 || tag != ACL_EXTENDED_ALLOW)
		return (0);
	if ((q = acl_get_qualifier(e)) == NULL)
		return (0);
	same = memcmp(q, a->who, sizeof(uuid_t)) == 0;
	acl_free(q);
	if (!same || acl_get_permset_mask_np(e, &m) != 0 || m != a->rights ||
	    acl_get_flagset_np(e, &fs) != 0)
		return (0);
	for (i = 0; i < NITEMS(acl_inherit); i++)
		if (acl_get_flag_np(fs, acl_inherit[i]) == 1)
			return (0);
	return (1);
}

/*
 * The ACL node_apply sets: the node's own with the entry --acl-remove
 * names taken out and every other entry left where it is (~/Library
 * carries Apple's). *prev is what the node held, for the journal. *next
 * stays NULL when there is nothing to change: no such entry marks it
 * absent, for the caller to report.
 */
static int
acl_next(tree_t *t, const node_t *n, const char *path, acl_t *prev,
    acl_t *next)
{
	aclspec_t *a = &t->acl;
	acl_entry_t e;
	int id, found = 0, err;

	*next = NULL;
	if (acl_read(n->fd, path, prev) != 0)
		return (EX_HELPER_OPFAIL);
	if (*prev == NULL) {
		a->absent = 1;
		return (EX_HELPER_OK);
	}
	if ((*next = acl_dup(*prev)) == NULL)
		fatal("out of memory");
	for (id = ACL_FIRST_ENTRY; !found &&
	    acl_get_entry(*next, id, &e) == 0; id = ACL_NEXT_ENTRY)
		found = acl_is_ours(e, a);
	if (found && acl_delete_entry(*next, e) == 0)
		return (EX_HELPER_OK);
	err = errno;
	acl_free(*next);
	*next = NULL;
	if (found) {
		errf("cannot take the ACL entry out (%s): %s",
		    strerror(err), path);
		return (EX_HELPER_OPFAIL);
	}
	a->absent = 1;
	return (EX_HELPER_OK);
}

/*
 * One node's change, on its own descriptor. The blocking bits come off first
 * when the owner, the mode or the ACL has to change, since each is refused
 * on an immutable or append-only node, root included; then the owner; then
 * the mode (the top node only, and never a link: a link's mode gates
 * nothing on macOS); then the ACL entry an unseal takes off, once the
 * owner bits are the invoker's way in again; then the flag word, as found
 * with the seal's flag added or the unseal's taken away. Journaled before
 * anything moves, the ACL as it was included. A seal changes the flag word
 * alone; owner, mode and ACL are the one-shot conversion's
 * (TODO(0.18.0): remove those with it).
 */
static int
node_apply(tree_t *t, const node_t *n, const char *path, const char *rel,
    int is_top)
{
	const struct stat *st = &n->st;
	uint32_t cur = st->st_flags, want;
	const char *what;
	acl_t prev = NULL, next = NULL;
	int own, mod, rc;

	want = t->sealing ? (cur | t->flag) : (cur & ~t->flag);
	if (t->sealing && S_ISREG(st->st_mode))
		iset_add(&t->flagged, st->st_dev, st->st_ino);
	own = t->chown && (st->st_uid != t->uid || st->st_gid != t->gid);
	mod = t->has_mode && is_top && !S_ISLNK(st->st_mode) &&
	    (st->st_mode & 07777) != t->mode;
	if (t->acl.op != 0 && is_top &&
	    (rc = acl_next(t, n, path, &prev, &next)) != EX_HELPER_OK) {
		if (prev != NULL)
			acl_free(prev);
		return (rc);
	}
	if (next == NULL && prev != NULL) {
		acl_free(prev);
		prev = NULL;
	}
	if (!own && !mod && next == NULL && want == cur)
		return (EX_HELPER_OK);
	journal_push(t, rel, st);
	if (next != NULL) {
		t->jv[t->jn - 1].acl_kept = 1;
		t->jv[t->jn - 1].acl = prev;
	}
	if ((own || mod || next != NULL) && (cur & BLOCKING_FLAGS) != 0) {
		cur &= ~(uint32_t)BLOCKING_FLAGS;
		what = "lift the flags on";
		if (fchflags(n->fd, cur) != 0)
			goto fail;
	}
	what = "change the owner of";
	if (own && fchown(n->fd, t->uid, t->gid) != 0)
		goto fail;
	what = "change the mode of";
	if (mod && fchmod(n->fd, t->mode) != 0)
		goto fail;
	what = "take the ACL entry off";
	if (next != NULL && acl_set_fd_np(n->fd, next, ACL_TYPE_EXTENDED) != 0)
		goto fail;
	what = "set the flags on";
	if (want != cur && fchflags(n->fd, want) != 0)
		goto fail;
	if (next != NULL)
		acl_free(next);
	return (EX_HELPER_OK);
fail:
	errf("cannot %s it (%s): %s", what, strerror(errno), path);
	if (next != NULL)
		acl_free(next);
	return (EX_HELPER_OPFAIL);
}

/*
 * A journaled ACL back as it was. An empty ACL is how the kernel is told
 * a node carries none (probed 2026-10-23: the node then reads back with
 * no ACL at all, as after chmod -a of its last entry).
 */
static int
acl_put_back(int fd, const jent_t *e)
{
	acl_t none = NULL;
	int rc;

	if (e->acl == NULL && (none = acl_init(1)) == NULL)
		return (-1);
	rc = acl_set_fd_np(fd, e->acl != NULL ? e->acl : none,
	    ACL_TYPE_EXTENDED);
	if (none != NULL)
		acl_free(none);
	return (rc);
}

/*
 * Reach a journaled node again from the held top descriptor, by its path
 * below the top, O_NOFOLLOW at every step, and put it back as it was. It must
 * still be the inode the journal names.
 */
static int
restore_one(const tree_t *t, const jent_t *e)
{
	struct stat st;
	char *buf, *p, *slash;
	uint32_t cur;
	int fd = -1, dfd, nfd, own, mod, rc = -1;

	if (e->rel[0] == '\0') {
		fd = dup_cloexec(t->topfd);
	} else {
		buf = xstrdup(e->rel);
		p = buf;
		dfd = dup_cloexec(t->topfd);
		while (dfd >= 0 && (slash = strchr(p, '/')) != NULL) {
			*slash = '\0';
			nfd = openat(dfd, p, O_SEARCH | O_NOFOLLOW |
			    O_CLOEXEC);
			close(dfd);
			dfd = nfd;
			p = slash + 1;
		}
		if (dfd >= 0) {
			fd = openat(dfd, p, O_RDONLY | O_NONBLOCK | O_CLOEXEC |
			    (e->type == S_IFDIR ? (O_DIRECTORY | O_NOFOLLOW) :
			    O_SYMLINK));
			close(dfd);
		}
		free(buf);
	}
	if (fd < 0)
		return (-1);
	if (fstat(fd, &st) != 0 || st.st_ino != e->ino ||
	    (st.st_mode & S_IFMT) != e->type)
		goto out;
	cur = st.st_flags;
	own = st.st_uid != e->uid || st.st_gid != e->gid;
	mod = e->type != S_IFLNK && (st.st_mode & 07777) != e->mode;
	if ((own || mod || e->acl_kept) && (cur & BLOCKING_FLAGS) != 0) {
		cur &= ~(uint32_t)BLOCKING_FLAGS;
		if (fchflags(fd, cur) != 0)
			goto out;
	}
	/* The entry goes back before the old owner does, so the invoker never
	 * loses their way in. */
	if (e->acl_kept && acl_put_back(fd, e) != 0)
		goto out;
	if (own && fchown(fd, e->uid, e->gid) != 0)
		goto out;
	if (mod && fchmod(fd, e->mode) != 0)
		goto out;
	if (cur != e->flags && fchflags(fd, e->flags) != 0)
		goto out;
	rc = 0;
out:
	close(fd);
	return (rc);
}

/*
 * Newest first, so a directory is put back after everything below it, while
 * it still holds them closed. A node that cannot be put back is named on a
 * window-open line, escaped: it is not as it was found.
 */
static int
rollback(const tree_t *t)
{
	size_t i;
	int bad = 0;

	for (i = t->jn; i > 0; i--) {
		const jent_t *e = &t->jv[i - 1];
		char *p;

		if (restore_one(t, e) == 0)
			continue;
		p = e->rel[0] == '\0' ? xstrdup(t->top) :
		    join_path(t->top, e->rel);
		errf("cannot put it back as it was: %s", p);
		fputs("window-open\t", stdout);
		print_escaped(p);
		fputc('\n', stdout);
		free(p);
		bad = 1;
	}
	return (bad);
}

/* Where a node sits: its parent, held, and its name there. A copy is
 * swapped in by that name. */
typedef struct {
	int		 pfd;
	const char	*ppath;		/* error text only */
	const char	*name;
} place_t;

typedef int (*walk_fn)(tree_t *, node_t *, const place_t *, const char *,
    const char *, int);

/*
 * Every entry of a held directory, each opened, checked and walked in turn.
 * The names are read first and the directory list freed after: by the time a
 * walk reads a directory it is frozen, so nothing can join it in between.
 */
static int
walk_children(tree_t *t, const node_t *dir, const char *path, const char *rel,
    int depth, walk_fn fn)
{
	elist_t names;
	size_t i;
	int rc = EX_HELPER_OK;

	if (depth >= MAX_DEPTH) {
		errf("refusing a tree deeper than %d levels: %s", MAX_DEPTH,
		    t->top);
		return (EX_HELPER_REFUSED);
	}
	if (snapshot(dir->fd, path, &names) != 0)
		return (EX_HELPER_OPFAIL);
	for (i = 0; i < names.n && rc == EX_HELPER_OK; i++) {
		const char *name = names.v[i].name;
		char *cpath = join_path(path, name);
		char *crel = rel_join(rel, name);
		place_t at;
		node_t c;

		at.pfd = dir->fd;
		at.ppath = path;
		at.name = name;
		rc = node_at(dir->fd, name, cpath, &c);
		if (rc == EX_HELPER_OK && c.st.st_dev != t->dev) {
			errf("refusing, a mount point inside the tree: %s",
			    cpath);
			rc = EX_HELPER_REFUSED;
		}
		if (rc == EX_HELPER_OK)
			rc = fn(t, &c, &at, cpath, crel, depth + 1);
		if (c.fd >= 0)
			close(c.fd);
		free(cpath);
		free(crel);
	}
	elist_free(&names);
	return (rc);
}

/*
 * Copy-and-swap, for one regular file a seal is about to flag. Root copies
 * it into its staging folder (data, extended attributes, ACL), gives the
 * copy the file's owner, group, mode, times and kept flags, and fingerprints
 * the copy there, where nothing else can reach it. One rename then swaps
 * the copy in and the original out, inside a window on the held parent:
 * its blocking flags come off for that one call, and when they did, the
 * parent's entries are compared across it (any other change is an
 * anomaly, reported at the end). The original must be what went out, and
 * must not have changed while it was copied; otherwise it is swapped back
 * and the seal refuses. On return *n is the copy, held, and the original
 * waits in staging for the end of the run.
 */
static int
swap_in(tree_t *t, node_t *n, const place_t *at, const char *path,
    const char *rel)
{
	char tmp[64], hex[65];
	struct stat cst, chk, now;
	struct timespec ts[2];
	struct attrlist al;
	elist_t before, after;
	expect_t exp;
	uint32_t pflags;
	const char *why = NULL;
	int cfd, slot = -1, lifted = 0, rc = EX_HELPER_OK, e;

	memset(&before, 0, sizeof(before));
	memset(&after, 0, sizeof(after));
	snprintf(tmp, sizeof(tmp), "swap.%d.%u", (int)getpid(), t->seq++);
	cfd = openat(t->sfd, tmp, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW |
	    O_CLOEXEC, 0600);
	if (cfd < 0) {
		errf("cannot create the copy in staging (%s): %s",
		    strerror(errno), path);
		return (EX_HELPER_OPFAIL);
	}
	ts[0] = n->st.st_atimespec;
	ts[1] = n->st.st_mtimespec;
	memset(&al, 0, sizeof(al));
	al.bitmapcount = ATTR_BIT_MAP_COUNT;
	al.commonattr = ATTR_CMN_CRTIME;
	if (fcopyfile(n->fd, cfd, NULL,
	    COPYFILE_DATA | COPYFILE_XATTR | COPYFILE_ACL) != 0 ||
	    fchown(cfd, n->st.st_uid, n->st.st_gid) != 0 ||
	    fchmod(cfd, n->st.st_mode & 07777) != 0 ||
	    futimens(cfd, ts) != 0 ||
	    fsetattrlist(cfd, &al, &n->st.st_birthtimespec,
	    sizeof(n->st.st_birthtimespec), 0) != 0 ||
	    fchflags(cfd, n->st.st_flags & KEPT_FLAGS) != 0 ||
	    sha256_fd(cfd, hex) != 0 || fstat(cfd, &cst) != 0) {
		errf("cannot make the copy to seal (%s): %s", strerror(errno),
		    path);
		close(cfd);
		(void)unlinkat(t->sfd, tmp, 0);
		return (EX_HELPER_OPFAIL);
	}

	if (fstat(at->pfd, &chk) != 0) {
		errf("cannot stat its folder (%s): %s", strerror(errno), path);
		close(cfd);
		(void)unlinkat(t->sfd, tmp, 0);
		return (EX_HELPER_OPFAIL);
	}
	pflags = chk.st_flags;
	if ((pflags & BLOCKING_FLAGS) != 0) {
		if (snapshot(at->pfd, at->ppath, &before) != 0) {
			close(cfd);
			(void)unlinkat(t->sfd, tmp, 0);
			return (EX_HELPER_OPFAIL);
		}
		slot = live_add(at->pfd, pflags, at->ppath);
		if (slot < 0 || fchflags(at->pfd,
		    pflags & ~(uint32_t)BLOCKING_FLAGS) != 0) {
			errf("cannot lift the flags on its folder (%s): %s",
			    strerror(errno), path);
			live_forget(slot);
			elist_free(&before);
			close(cfd);
			(void)unlinkat(t->sfd, tmp, 0);
			return (EX_HELPER_OPFAIL);
		}
		lifted = 1;
	}

	if (renameatx_np(t->sfd, tmp, at->pfd, at->name, RENAME_SWAP) != 0) {
		e = errno;
		if (e == EXDEV)
			errf("refusing, it is not on the volume of locked's "
			    "staging, so no copy can be swapped in: %s", path);
		else
			errf("cannot swap the copy in (%s): %s", strerror(e),
			    path);
		rc = e == EXDEV ? EX_HELPER_REFUSED : EX_HELPER_OPFAIL;
		(void)unlinkat(t->sfd, tmp, 0);
		goto restore;
	}
	if (fstatat(t->sfd, tmp, &chk, AT_SYMLINK_NOFOLLOW) != 0 ||
	    chk.st_ino != n->st.st_ino || chk.st_dev != n->st.st_dev ||
	    fstatat(at->pfd, at->name, &now, AT_SYMLINK_NOFOLLOW) != 0 ||
	    now.st_ino != cst.st_ino)
		why = "it was replaced while it was sealed";
	else if (fstat(n->fd, &now) != 0 || now.st_size != n->st.st_size ||
	    now.st_mtimespec.tv_sec != n->st.st_mtimespec.tv_sec ||
	    now.st_mtimespec.tv_nsec != n->st.st_mtimespec.tv_nsec)
		why = "it changed while it was copied; run the lock again";
	if (why != NULL) {
		/* Back as it was. Only a swap back that put the copy in staging
		 * leaves anything there to remove. */
		if (renameatx_np(t->sfd, tmp, at->pfd, at->name,
		    RENAME_SWAP) == 0 &&
		    fstatat(t->sfd, tmp, &chk, AT_SYMLINK_NOFOLLOW) == 0 &&
		    chk.st_ino == cst.st_ino)
			(void)unlinkat(t->sfd, tmp, 0);
		else
			errf("the file that went out is kept in staging as "
			    "%s: %s", tmp, path);
		errf("refusing, %s: %s", why, path);
		rc = EX_HELPER_REFUSED;
		goto restore;
	}
	elist_push(&t->staged, tmp, n->st.st_dev, n->st.st_ino);
	print_sum(hex, rel);
	close(n->fd);
	n->fd = cfd;
	n->st = cst;
	cfd = -1;
	if (rel[0] == '\0')
		t->topfd = n->fd;

restore:
	if (cfd >= 0)
		close(cfd);
	if (lifted) {
		if (live_restore(slot, at->ppath) != 0)
			rc = EX_HELPER_WINOPEN;
		else if (rc == EX_HELPER_OK &&
		    snapshot(at->pfd, at->ppath, &after) == 0) {
			memset(&exp, 0, sizeof(exp));
			exp.swapped = at->name;
			exp.swap_ino = n->st.st_ino;
			t->anomalies += diff_report(&before, &after, &exp);
		} else if (rc == EX_HELPER_OK) {
			t->anomalies++;
		}
	}
	elist_free(&before);
	elist_free(&after);
	return (rc);
}

/*
 * Lock direction, top-down. Each directory is frozen BEFORE its entries are
 * read: a system flag binds the owner too, so once it is on, no process
 * running as the user can add, remove or rename an entry. The list read
 * after that is the final one, so anything planted while the directory was
 * still open is on it and meets the gate like every other entry. Each
 * regular file is swapped for a copy first (with --swap), then flagged.
 */
static int
seal_walk(tree_t *t, node_t *n, const place_t *at, const char *path,
    const char *rel, int depth)
{
	int rc;

	if ((rc = visit(t, path)) != EX_HELPER_OK)
		return (rc);
	if (depth > 0) {
		/* A second name for a file this walk already sealed. */
		if (n->st.st_nlink > 1 && !S_ISDIR(n->st.st_mode) &&
		    journal_has(t, n->st.st_ino))
			return (EX_HELPER_OK);
		rc = gate(n, path, t->owners, 1);
		if (rc != EX_HELPER_OK)
			return (rc);
	}
	if (t->swap && S_ISREG(n->st.st_mode) &&
	    (rc = swap_in(t, n, at, path, rel)) != EX_HELPER_OK)
		return (rc);
	rc = node_apply(t, n, path, rel, depth == 0);
	if (rc != EX_HELPER_OK || !S_ISDIR(n->st.st_mode) || !t->recursive)
		return (rc);
	return (walk_children(t, n, path, rel, depth, seal_walk));
}

/*
 * Unlock direction, first pass: every directory frozen with the flag the
 * unseal clears before it is read, every node gated, nothing else changed.
 * A sealed tree is frozen already, so this pass changes nothing on one in
 * order; a refusal rolls back any freeze it did apply.
 */
static int
check_walk(tree_t *t, node_t *n, const place_t *at, const char *path,
    const char *rel, int depth)
{
	(void)at;
	if (visit(t, path) != EX_HELPER_OK)
		return (EX_HELPER_REFUSED);
	if (depth > 0 && gate(n, path, t->owners, 0) != EX_HELPER_OK)
		return (EX_HELPER_REFUSED);
	if (!S_ISDIR(n->st.st_mode))
		return (EX_HELPER_OK);
	if ((n->st.st_flags & t->flag) == 0) {
		journal_push(t, rel, &n->st);
		if (fchflags(n->fd, n->st.st_flags | t->flag) != 0) {
			errf("cannot freeze it (%s): %s", strerror(errno),
			    path);
			return (EX_HELPER_OPFAIL);
		}
	}
	return (walk_children(t, n, path, rel, depth, check_walk));
}

/*
 * Unlock direction, second pass, bottom-up: everything below a directory is
 * released while the directory is still frozen, and the directory last.
 * A node already in the state the unseal asks for (a second name for a file
 * released further up the walk) is left alone.
 */
static int
unseal_walk(tree_t *t, node_t *n, const place_t *at, const char *path,
    const char *rel, int depth)
{
	int rc;

	(void)at;
	if ((rc = visit(t, path)) != EX_HELPER_OK)
		return (rc);
	if (depth > 0) {
		if ((!t->chown || (n->st.st_uid == t->uid &&
		    n->st.st_gid == t->gid)) && (n->st.st_flags & t->flag) == 0)
			return (EX_HELPER_OK);
		rc = gate(n, path, t->owners, 0);
		if (rc != EX_HELPER_OK)
			return (rc);
	}
	if (S_ISDIR(n->st.st_mode) && t->recursive) {
		rc = walk_children(t, n, path, rel, depth, unseal_walk);
		if (rc != EX_HELPER_OK)
			return (rc);
	}
	return (node_apply(t, n, path, rel, depth == 0));
}

/*
 * The read-only first pass: every node the verb would reach, counted and
 * left as it is. A count other than the plan's refuses before the first
 * change, naming the number found.
 */
static int
count_walk(tree_t *t, node_t *n, const place_t *at, const char *path,
    const char *rel, int depth)
{
	(void)at;
	t->seen++;
	if (!S_ISDIR(n->st.st_mode) || !t->recursive)
		return (EX_HELPER_OK);
	return (walk_children(t, n, path, rel, depth, count_walk));
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

/*
 * The source of copy and xattrs-from: a regular file, reached from "/" as
 * --as wherever --as owns the path (open_parent, node_at_as), pinned by
 * identity and gated by owner on the descriptor it returns in *sfd. Back in
 * this process's own identity on return, whatever the outcome.
 */
static int
open_source(const opts_t *o, const reader_t *r, const owners_t *owners,
    const nodeid_t *sid, int *sfd, struct stat *st)
{
	char buf[PATH_MAX];
	const char *leaf;
	node_t n;
	int pfd, inr = 1, rc;

	*sfd = -1;
	pfd = open_parent(o->src, buf, sizeof(buf), &leaf, r, &inr);
	if (pfd < 0) {
		become_self();
		return (pfd == -2 ? EX_HELPER_REFUSED : EX_HELPER_OPFAIL);
	}
	rc = node_at_as(pfd, leaf, o->src, &n, r, &inr);
	become_self();
	close(pfd);
	if (rc != EX_HELPER_OK)
		return (rc);
	*st = n.st;
	if (!S_ISREG(st->st_mode)) {
		errf("%s is not a regular file", o->src);
		close(n.fd);
		return (EX_HELPER_OPFAIL);
	}
	if (check_id("source", o->src, sid, st, at_fd(n.fd)) != 0) {
		close(n.fd);
		return (EX_HELPER_IDENT);
	}
	/* Root reads only what the owner gate lets through: a file the
	 * invoker owns, or one sealed for them -- never a second name the
	 * invoker planted for somebody else's file. */
	if (gate_owner(st, o->src, owners) != EX_HELPER_OK) {
		close(n.fd);
		return (EX_HELPER_REFUSED);
	}
	*sfd = n.fd;
	return (EX_HELPER_OK);
}

/* --owner and --as, shared by the copy verbs. */
static int
parse_source(const opts_t *o, owners_t *owners, reader_t *r)
{
	if (need(o->owner, "--owner") != 0 || need(o->as, "--as") != 0)
		return (-1);
	if (parse_owners(o->owner, owners) != 0) {
		errf("--owner is not a list of accounts");
		return (-1);
	}
	if (parse_reader(o->as, owners, r) != 0) {
		errf("--as is not an account");
		return (-1);
	}
	return (0);
}

static int
cmd_copy(int argc, char **argv)
{
	opts_t o;
	nodeid_t sid;
	owners_t owners;
	reader_t r;
	struct stat st;
	int sfd = -1, dfd = -1, status = EX_HELPER_OK;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.src, "--src") != 0 || need_abs(o.dest, "--dest") != 0 ||
	    parse_ids(o.src_id, &sid, "--src-id") != 0 ||
	    parse_source(&o, &owners, &r) != 0)
		return (EX_HELPER_USAGE);
	TEST_PAUSE("copy");

	status = open_source(&o, &r, &owners, &sid, &sfd, &st);
	if (status != EX_HELPER_OK)
		goto cleanup;
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
 * The source is pinned by identity, and gated by owner: the caller names
 * whose it may be (the lock account for a sealed file, the invoker for an
 * anchor-tier node such as ~/.ssh/config), and the recorded identity says
 * exactly which node this has to be. The destination must be root-owned: it
 * is the staging file the caller just created, and anything else is not ours
 * to write to.
 */
static int
cmd_xattrs_from(int argc, char **argv)
{
	opts_t o;
	nodeid_t sid;
	owners_t owners;
	reader_t r;
	struct stat st;
	int sfd = -1, dfd = -1, status = EX_HELPER_OK;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.src, "--src") != 0 || need_abs(o.dest, "--dest") != 0 ||
	    parse_ids(o.src_id, &sid, "--src-id") != 0 ||
	    parse_source(&o, &owners, &r) != 0)
		return (EX_HELPER_USAGE);

	/* Attributes are read like bytes: as --as where it owns the path,
	 * and only through the owner gate. */
	status = open_source(&o, &r, &owners, &sid, &sfd, &st);
	if (status != EX_HELPER_OK)
		goto cleanup;

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

/* ---- verbs: seal and unseal --------------------------------------------- */

/*
 * A seal or an unseal runs to its end or rolls back, and the roll back needs
 * the walk to finish first: a Ctrl-C or a kill waits until the verb returns
 * and then dies with the process, which discards it. The bash side's own
 * trap still sees it.
 */
static void
block_signals(void)
{
	sigset_t s;

	sigemptyset(&s);
	sigaddset(&s, SIGINT);
	sigaddset(&s, SIGTERM);
	sigaddset(&s, SIGHUP);
	(void)sigprocmask(SIG_BLOCK, &s, NULL);
}

/*
 * A folder only root may enter or change, held: root's, no group or other
 * bits. Staging for --stage and install's --src. "Root" is this process's
 * own account, which the root gate makes root in every release run; a
 * test build run by a user takes that user's own folder.
 */
static int
open_root_dir(const char *path, const char *what, int *out)
{
	char buf[PATH_MAX];
	const char *leaf;
	node_t d;
	int pfd, rc;

	*out = -1;
	pfd = open_parent(path, buf, sizeof(buf), &leaf, NULL, NULL);
	if (pfd < 0)
		return (pfd == -2 ? EX_HELPER_REFUSED : EX_HELPER_OPFAIL);
	rc = node_at(pfd, leaf, path, &d);
	close(pfd);
	if (rc != EX_HELPER_OK)
		return (rc);
	if (!S_ISDIR(d.st.st_mode) || d.st.st_uid != g_self_uid ||
	    (d.st.st_mode & 077) != 0) {
		errf("refusing, %s is not a folder only root may enter: %s",
		    what, path);
		close(d.fd);
		return (EX_HELPER_REFUSED);
	}
	*out = d.fd;
	return (EX_HELPER_OK);
}

/* Remove the originals a swap parked in staging. One that will not go is
 * named and left: it is root's, in root's folder. */
static void
staged_drop(tree_t *t)
{
	size_t i;

	for (i = 0; i < t->staged.n; i++)
		if (unlinkat(t->sfd, t->staged.v[i].name, 0) != 0)
			errf("cannot remove a swapped-out file from staging "
			    "(%s): %s", strerror(errno), t->staged.v[i].name);
	elist_free(&t->staged);
}

/*
 * seal: add --flag to the flag word of the node at --path and, with
 * --recursive, of every node under it. unseal: take it away. Every node
 * must be a directory, a regular file or a symlink, owned by one of
 * --owner; the top node must also be --id. A seal refuses a set-user-id or
 * set-group-id file. On any refusal or failure everything already changed
 * is put back (a file already swapped stays the copy).
 *
 * seal --swap --stage DIR: each regular file is swapped for a copy made in
 * DIR first (swap_in), and its fingerprint printed. DIR must be root's
 * alone, on the volume of the files.
 *
 * unseal --recursive runs in two passes: the first freezes every directory
 * before reading it and gates every node, changing nothing else, so a
 * refusal finds the tree as it was; the second releases the nodes, bottom
 * up.
 *
 * Before either verb changes anything, a read-only pass counts the nodes it
 * would reach: --count's 1 for a single node, the whole tree with
 * --recursive. Any other number refuses, and every pass after it is held
 * to the same count (visit).
 *
 * After a seal, every process holding one of the sealed files open for
 * writing is named (writer_scan): exit 8, the seal done.
 *
 * --chown, --mode and --acl-remove serve the one-shot conversion from the
 * lock-account seals of 0.16 and earlier: an unseal hands a node back to
 * its recorded owner, and takes a placement directory's ACL entry off.
 * TODO(0.18.0): remove with the conversion.
 */
static int
cmd_tree(int argc, char **argv, int sealing)
{
	opts_t o;
	nodeid_t want;
	owners_t owners;
	tree_t t;
	node_t top;
	place_t at;
	char buf[PATH_MAX], pdir[PATH_MAX], *slash;
	const char *leaf;
	int pfd, rc, hits;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.path, "--path") != 0 ||
	    parse_ids(o.id, &want, "--id") != 0 ||
	    need(o.owner, "--owner") != 0 || need(o.flag, "--flag") != 0 ||
	    need(o.count, "--count") != 0)
		return (EX_HELPER_USAGE);
	memset(&t, 0, sizeof(t));
	t.sfd = -1;
	if (parse_owners(o.owner, &owners) != 0) {
		errf("--owner is not a list of accounts");
		return (EX_HELPER_USAGE);
	}
	if (parse_count(o.count, &t.plan) != 0) {
		errf("--count must be a number of nodes, 1 or more");
		return (EX_HELPER_USAGE);
	}
	if (!o.recursive && t.plan != 1) {
		errf("--count must be 1 without --recursive");
		return (EX_HELPER_USAGE);
	}
	if (parse_flag(o.flag, &t.flag) != 0) {
		errf("--flag must be one of uchg, uappnd, schg, sappnd");
		return (EX_HELPER_USAGE);
	}
	if (o.chown != NULL) {
		if (sealing) {
			errf("--chown is for unseal");
			return (EX_HELPER_USAGE);
		}
		if (parse_chown(o.chown, &t.uid, &t.gid) != 0) {
			errf("--chown must be <user>:<group>");
			return (EX_HELPER_USAGE);
		}
		t.chown = 1;
	}
	if (o.mode != NULL) {
		if (sealing) {
			errf("--mode is for unseal");
			return (EX_HELPER_USAGE);
		}
		if (parse_mode(o.mode, &t.mode) != 0) {
			errf("--mode must be octal permission bits");
			return (EX_HELPER_USAGE);
		}
		t.has_mode = 1;
	}
	/* A tree is frozen whole: every directory and file immutable. An
	 * unseal's first pass freezes with the flag it clears, so any other
	 * flag would leave those freezes behind. */
	if (o.recursive && t.flag != SF_IMMUTABLE && t.flag != UF_IMMUTABLE) {
		errf("--recursive takes --flag schg or uchg");
		return (EX_HELPER_USAGE);
	}
	if ((o.swap || o.stage != NULL) && !sealing) {
		errf("--swap and --stage are for seal");
		return (EX_HELPER_USAGE);
	}
	if (o.swap != (o.stage != NULL)) {
		errf("--swap and --stage go together");
		return (EX_HELPER_USAGE);
	}
	if (o.stage != NULL && need_abs(o.stage, "--stage") != 0)
		return (EX_HELPER_USAGE);
	if (o.acl_remove != NULL) {
		if (sealing) {
			errf("--acl-remove is for unseal");
			return (EX_HELPER_USAGE);
		}
		/* One entry on one directory: nothing below it is the
		 * placement seal's. */
		if (o.recursive) {
			errf("--acl-remove takes a single node, never "
			    "--recursive");
			return (EX_HELPER_USAGE);
		}
		if (parse_acl(o.acl_remove, "--acl-remove", &t.acl) != 0)
			return (EX_HELPER_USAGE);
		t.acl.op = -1;
	}
	t.sealing = sealing;
	t.owners = &owners;
	t.recursive = o.recursive;
	t.swap = o.swap;
	t.top = o.path;
	t.topfd = -1;

	TEST_PAUSE(sealing ? "seal" : "unseal");
	block_signals();

	if (o.stage != NULL &&
	    (rc = open_root_dir(o.stage, "--stage", &t.sfd)) != EX_HELPER_OK)
		return (rc);
	pfd = open_parent(o.path, buf, sizeof(buf), &leaf, NULL, NULL);
	if (pfd < 0) {
		rc = pfd == -2 ? EX_HELPER_REFUSED : EX_HELPER_OPFAIL;
		goto done;
	}
	rc = node_at(pfd, leaf, o.path, &top);
	if (rc != EX_HELPER_OK) {
		close(pfd);
		goto done;
	}
	/* A link has no descriptor getattrlist answers for; its volume is
	 * asked by the held parent and the name, never by a path. */
	if (check_id("node", o.path, &want, &top.st, S_ISLNK(top.st.st_mode) ?
	    at_name(pfd, leaf) : at_fd(top.fd)) != 0) {
		close(pfd);
		close(top.fd);
		rc = EX_HELPER_IDENT;
		goto done;
	}
	rc = gate(&top, o.path, &owners, sealing);
	if (rc == EX_HELPER_OK && t.acl.op != 0 &&
	    !S_ISDIR(top.st.st_mode)) {
		errf("refusing, an ACL entry goes on a directory only: %s",
		    o.path);
		rc = EX_HELPER_REFUSED;
	}
	if (rc != EX_HELPER_OK) {
		close(pfd);
		close(top.fd);
		goto done;
	}
	t.dev = top.st.st_dev;
	t.topfd = top.fd;
	/* The top's folder stays held: a file at the top is swapped in by
	 * its name there. The walk reached it for search only, and a swap's
	 * entry diff lists it, so it is held readable from here. */
	if ((rc = openat(pfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
		errf("cannot open its folder (%s): %s", strerror(errno),
		    o.path);
		close(pfd);
		close(top.fd);
		rc = EX_HELPER_OPFAIL;
		goto done;
	}
	close(pfd);
	pfd = rc;
	rc = EX_HELPER_OK;
	strlcpy(pdir, o.path, sizeof(pdir));
	slash = strrchr(pdir, '/');
	if (slash == pdir)
		slash[1] = '\0';
	else
		*slash = '\0';
	at.pfd = pfd;
	at.ppath = pdir;
	at.name = leaf;

	rc = count_walk(&t, &top, &at, o.path, "", 0);
	if (rc == EX_HELPER_OK)
		rc = count_matches(&t, "the tree holds");
	if (rc != EX_HELPER_OK)
		goto close_top;
	/* The moment between the count and the first change, held open in a
	 * test build so a test can plant a node the count did not see. */
	TEST_PAUSE(sealing ? "seal-walk" : "unseal-walk");

	t.seen = 0;
	if (sealing) {
		rc = seal_walk(&t, &top, &at, o.path, "", 0);
		if (rc == EX_HELPER_OK)
			rc = count_matches(&t, "the seal reached");
	} else {
		/* Only a tree has a first pass. A single node (a file, a link,
		 * or a directory such as a chain folder whose entries are not
		 * part of the seal) was gated above, and nothing below it is
		 * read, gated or frozen. */
		if (t.recursive) {
			rc = check_walk(&t, &top, &at, o.path, "", 0);
			if (rc == EX_HELPER_OK)
				rc = count_matches(&t, "the first pass reached");
			t.seen = 0;
		}
		/* The first pass may have frozen the top; the second reads
		 * its flag word as it now is. */
		if (t.recursive && rc == EX_HELPER_OK &&
		    fstat(top.fd, &top.st) != 0) {
			errf("cannot stat (%s): %s", strerror(errno), o.path);
			rc = EX_HELPER_OPFAIL;
		}
		if (rc == EX_HELPER_OK)
			rc = unseal_walk(&t, &top, &at, o.path, "", 0);
		if (rc == EX_HELPER_OK)
			rc = count_matches(&t, "the unseal reached");
	}
	if (rc != EX_HELPER_OK && rollback(&t) != 0)
		rc = EX_HELPER_WINOPEN;
	if (rc == EX_HELPER_OK && t.acl.absent) {
		fputs("acl-absent\t", stdout);
		print_escaped(o.path);
		fputc('\n', stdout);
	}
	if (rc == EX_HELPER_OK && t.anomalies > 0)
		rc = EX_HELPER_ANOMALY;
	if ((rc == EX_HELPER_OK || rc == EX_HELPER_ANOMALY) && sealing) {
		hits = writer_scan(&t.flagged);
		if (hits != 0)
			rc = EX_HELPER_WRITER;
	}
close_top:
	journal_free(&t);
	close(top.fd);
	close(pfd);
done:
	if (t.sfd >= 0) {
		staged_drop(&t);
		close(t.sfd);
	}
	iset_free(&t.flagged);
	return (rc);
}

/* ---- verb: copy-tree ---------------------------------------------------- */

typedef struct {
	const owners_t	*owners;
	const reader_t	*reader;
	uid_t		 uid;
	gid_t		 gid;
	dev_t		 dev;
	const char	*top;
} ctree_t;

static int copy_dir(ctree_t *, int, const char *, int, int, int);

/*
 * A link's text is read by name: macOS refuses read(2) on a link's own
 * descriptor. The text is no secret -- readlink needs no permission on the
 * link -- and the entry must still be the inode the gate passed.
 */
static int
copy_link(const ctree_t *c, int sfd, const char *name, const char *path,
    const node_t *n, int dfd)
{
	char target[PATH_MAX + 1];
	struct stat after;
	ssize_t k;

	k = readlinkat(sfd, name, target, PATH_MAX);
	if (k < 0 || k >= PATH_MAX) {
		errf("cannot read the link (%s): %s",
		    k < 0 ? strerror(errno) : "too long", path);
		return (EX_HELPER_OPFAIL);
	}
	target[k] = '\0';
	if (fstatat(sfd, name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
	    after.st_ino != n->st.st_ino || !S_ISLNK(after.st_mode)) {
		errf("refusing, it changed while it was read: %s", path);
		return (EX_HELPER_REFUSED);
	}
	if (symlinkat(target, dfd, name) != 0 ||
	    fchownat(dfd, name, c->uid, c->gid, AT_SYMLINK_NOFOLLOW) != 0) {
		errf("cannot copy the link (%s): %s", strerror(errno), path);
		return (EX_HELPER_OPFAIL);
	}
	return (EX_HELPER_OK);
}

/*
 * One entry: opened as --as while `inr` holds (node_at_as), gated like a
 * seal's, then copied from its own descriptor, as this process. Permission
 * bits travel without the set-user-id, set-group-id and sticky bits; the
 * owner is --chown's; data, extended attributes and ACLs travel for a
 * file. Flags never do.
 */
static int
copy_entry(ctree_t *c, int sfd, const char *spath, int dfd, const char *name,
    int depth, int inr)
{
	char *path = join_path(spath, name);
	node_t n;
	int rc, ofd = -1;

	rc = node_at_as(sfd, name, path, &n, c->reader, &inr);
	become_self();
	if (rc == EX_HELPER_OK && n.st.st_dev != c->dev) {
		errf("refusing, a mount point inside the tree: %s", path);
		rc = EX_HELPER_REFUSED;
	}
	if (rc == EX_HELPER_OK)
		rc = gate(&n, path, c->owners, 0);
	if (rc != EX_HELPER_OK)
		goto out;
	if (S_ISDIR(n.st.st_mode)) {
		if (mkdirat(dfd, name, 0700) != 0 ||
		    (ofd = openat(dfd, name, O_RDONLY | O_DIRECTORY |
		    O_NOFOLLOW | O_CLOEXEC)) < 0) {
			errf("cannot create the copy (%s): %s",
			    strerror(errno), path);
			rc = EX_HELPER_OPFAIL;
			goto out;
		}
		rc = copy_dir(c, n.fd, path, ofd, depth + 1, inr);
	} else if (S_ISREG(n.st.st_mode)) {
		ofd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL |
		    O_NOFOLLOW | O_CLOEXEC, 0600);
		if (ofd < 0 || fcopyfile(n.fd, ofd, NULL,
		    COPYFILE_DATA | COPYFILE_XATTR | COPYFILE_ACL) != 0) {
			errf("cannot copy (%s): %s", strerror(errno), path);
			rc = EX_HELPER_OPFAIL;
			goto out;
		}
	} else {
		rc = copy_link(c, sfd, name, path, &n, dfd);
		goto out;
	}
	if (rc == EX_HELPER_OK && (fchown(ofd, c->uid, c->gid) != 0 ||
	    fchmod(ofd, n.st.st_mode & 0777) != 0)) {
		errf("cannot set the owner and mode of the copy (%s): %s",
		    strerror(errno), path);
		rc = EX_HELPER_OPFAIL;
	}
out:
	if (ofd >= 0)
		close(ofd);
	if (n.fd >= 0)
		close(n.fd);
	free(path);
	return (rc);
}

static int
copy_dir(ctree_t *c, int sfd, const char *spath, int dfd, int depth, int inr)
{
	elist_t names;
	size_t i;
	int rc = EX_HELPER_OK;

	if (depth >= MAX_DEPTH) {
		errf("refusing a tree deeper than %d levels: %s", MAX_DEPTH,
		    c->top);
		return (EX_HELPER_REFUSED);
	}
	if (snapshot(sfd, spath, &names) != 0)
		return (EX_HELPER_OPFAIL);
	for (i = 0; i < names.n && rc == EX_HELPER_OK; i++)
		rc = copy_entry(c, sfd, spath, dfd, names.v[i].name, depth,
		    inr);
	elist_free(&names);
	return (rc);
}

/*
 * copy-tree: copy the folder at --src, every node of it gated as a seal
 * gates them (a directory, a file or a symlink, owned by one of --owner),
 * into a new folder at --dest owned by --chown. This is what root reads a
 * folder through -- its snapshot and the diff witness above a relock -- so
 * no inode the owner gate refuses is ever read, whatever was linked or
 * renamed into the folder.
 *
 * --dest is root's own staging, created here and never present before; it
 * is named by path the way `copy` names its destination. On failure the
 * partial copy is left for the caller to remove.
 */
static int
cmd_copy_tree(int argc, char **argv)
{
	opts_t o;
	nodeid_t sid;
	owners_t owners;
	reader_t r;
	ctree_t c;
	node_t top;
	char buf[PATH_MAX];
	const char *leaf;
	int pfd, dfd = -1, inr = 1, rc;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.src, "--src") != 0 || need_abs(o.dest, "--dest") != 0 ||
	    parse_ids(o.src_id, &sid, "--src-id") != 0 ||
	    need(o.chown, "--chown") != 0 ||
	    parse_source(&o, &owners, &r) != 0)
		return (EX_HELPER_USAGE);
	memset(&c, 0, sizeof(c));
	if (parse_chown(o.chown, &c.uid, &c.gid) != 0) {
		errf("--chown must be <user>:<group>");
		return (EX_HELPER_USAGE);
	}
	c.owners = &owners;
	c.reader = &r;
	c.top = o.src;

	TEST_PAUSE("copy-tree");

	pfd = open_parent(o.src, buf, sizeof(buf), &leaf, &r, &inr);
	if (pfd < 0) {
		become_self();
		return (pfd == -2 ? EX_HELPER_REFUSED : EX_HELPER_OPFAIL);
	}
	rc = node_at_as(pfd, leaf, o.src, &top, &r, &inr);
	become_self();
	close(pfd);
	if (rc != EX_HELPER_OK)
		return (rc);
	if (check_id("source", o.src, &sid, &top.st, at_fd(top.fd)) != 0) {
		close(top.fd);
		return (EX_HELPER_IDENT);
	}
	rc = gate(&top, o.src, &owners, 0);
	if (rc == EX_HELPER_OK && !S_ISDIR(top.st.st_mode)) {
		errf("not a directory: %s", o.src);
		rc = EX_HELPER_OPFAIL;
	}
	if (rc != EX_HELPER_OK) {
		close(top.fd);
		return (rc);
	}
	c.dev = top.st.st_dev;

	if (mkdir(o.dest, 0700) != 0 ||
	    (dfd = open(o.dest, O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
	    O_CLOEXEC)) < 0) {
		errf("cannot create (%s): %s", strerror(errno), o.dest);
		close(top.fd);
		return (EX_HELPER_OPFAIL);
	}
	rc = copy_dir(&c, top.fd, o.src, dfd, 0, inr);
	if (rc == EX_HELPER_OK && (fchown(dfd, c.uid, c.gid) != 0 ||
	    fchmod(dfd, top.st.st_mode & 0777) != 0)) {
		errf("cannot set the owner and mode of the copy (%s): %s",
		    strerror(errno), o.dest);
		rc = EX_HELPER_OPFAIL;
	}
	close(dfd);
	close(top.fd);
	return (rc);
}

/* ---- verb: install ------------------------------------------------------ */

/*
 * install: put an approved file in place, sealed. --src is the staged file,
 * root's, in a folder only root may enter, on the volume of --parent. It
 * takes --chown and --mode while it is still there, and its fingerprint is
 * taken there. Then, inside a window on the held parent, one rename puts
 * it at --name: swapped with the sealed file --target-id names (owned by
 * one of --owner; its flag lifted for the swap, the inode that went out
 * checked, then removed from staging), or, with --new, at a name nothing
 * holds yet. The flag (none: no flag, for a revert of a file that is
 * unlocked) goes on through the held descriptor of the new file,
 * and every process holding it open for writing is named (exit 8, the
 * install done). When the parent's own flags had to come off, its entries
 * are compared across the window (exit 6 on any other change).
 */
static int
cmd_install(int argc, char **argv)
{
	opts_t o;
	nodeid_t pid, tid;
	owners_t owners;
	window_t w;
	target_t t;
	expect_t exp;
	node_t src;
	iset_t one;
	struct stat chk, out;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	uint32_t flag, keep = 0;
	char sbuf[PATH_MAX], hex[65];
	const char *sleaf;
	int sdir = -1, rc, status = EX_HELPER_OK, moved = 0, hits;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.src, "--src") != 0 ||
	    need_abs(o.parent, "--parent") != 0 ||
	    need_component(o.name, "--name") != 0 ||
	    parse_ids(o.parent_id, &pid, "--parent-id") != 0 ||
	    need(o.chown, "--chown") != 0 || need(o.mode, "--mode") != 0 ||
	    need(o.flag, "--flag") != 0)
		return (EX_HELPER_USAGE);
	if (o.new_node && (o.target_id != NULL || o.owner != NULL)) {
		errf("--new names no target; --target-id and --owner do not apply");
		return (EX_HELPER_USAGE);
	}
	if (!o.new_node && (parse_ids(o.target_id, &tid, "--target-id") != 0 ||
	    need(o.owner, "--owner") != 0))
		return (EX_HELPER_USAGE);
	if (!o.new_node && !tid.given) {
		errf("--target-id must name the sealed file");
		return (EX_HELPER_USAGE);
	}
	if (!o.new_node && parse_owners(o.owner, &owners) != 0) {
		errf("--owner is not a list of accounts");
		return (EX_HELPER_USAGE);
	}
	if (parse_chown(o.chown, &uid, &gid) != 0) {
		errf("--chown must be <user>:<group>");
		return (EX_HELPER_USAGE);
	}
	if (parse_mode(o.mode, &mode) != 0 || (mode & (S_ISUID | S_ISGID))) {
		errf("--mode must be octal permission bits, no set-id bit");
		return (EX_HELPER_USAGE);
	}
	/* none: a revert of a file that is unlocked puts it back unsealed. */
	if (strcmp(o.flag, "none") == 0)
		flag = 0;
	else if (parse_flag(o.flag, &flag) != 0) {
		errf("--flag must be one of uchg, uappnd, schg, sappnd, none");
		return (EX_HELPER_USAGE);
	}

	window_init(&w);
	target_init(&t);
	memset(&one, 0, sizeof(one));
	src.fd = -1;
	TEST_PAUSE("install");

	/* The staged file: root's, alone in name, in root's own folder (this
	 * process's account, as open_root_dir takes it). */
	sdir = open_parent(o.src, sbuf, sizeof(sbuf), &sleaf, NULL, NULL);
	if (sdir < 0)
		return (sdir == -2 ? EX_HELPER_REFUSED : EX_HELPER_OPFAIL);
	if (fstat(sdir, &chk) != 0 || chk.st_uid != g_self_uid ||
	    (chk.st_mode & 077) != 0) {
		errf("refusing, the staged file is not in a folder only root "
		    "may enter: %s", o.src);
		close(sdir);
		return (EX_HELPER_REFUSED);
	}
	rc = node_at(sdir, sleaf, o.src, &src);
	if (rc == EX_HELPER_OK && (!S_ISREG(src.st.st_mode) ||
	    src.st.st_uid != g_self_uid || src.st.st_nlink != 1)) {
		errf("refusing, the staged file is not a regular file of "
		    "root's with one name: %s", o.src);
		rc = EX_HELPER_REFUSED;
	}
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}

	rc = window_open(&w, o.parent, &pid);
	if (rc != EX_HELPER_OK) {
		status = rc;
		goto cleanup;
	}
	if (w.st.st_dev != src.st.st_dev) {
		errf("refusing, it is not on the volume of locked's staging: "
		    "%s", o.parent);
		status = EX_HELPER_REFUSED;
		goto cleanup;
	}
	if (o.new_node) {
		if (fstatat(w.fd, o.name, &chk, AT_SYMLINK_NOFOLLOW) == 0 ||
		    errno != ENOENT) {
			errf("refusing, something is already at the new "
			    "name: %s/%s", o.parent, o.name);
			status = EX_HELPER_REFUSED;
			goto cleanup;
		}
	} else {
		rc = target_open(&t, w.fd, o.parent, o.name, &tid);
		if (rc == EX_HELPER_OK && (t.fd < 0 || !S_ISREG(t.st.st_mode))) {
			errf("refusing, not a regular file: %s", t.path);
			rc = EX_HELPER_REFUSED;
		}
		if (rc == EX_HELPER_OK)
			rc = gate_owner(&t.st, t.path, &owners);
		if (rc != EX_HELPER_OK) {
			status = rc;
			goto cleanup;
		}
		keep = t.st.st_flags & KEPT_FLAGS;
	}

	/* Owner, mode and kept flags while the file is still out of reach,
	 * and the fingerprint of exactly these bytes. */
	if (fchown(src.fd, uid, gid) != 0 || fchmod(src.fd, mode) != 0 ||
	    fchflags(src.fd, keep) != 0 || sha256_fd(src.fd, hex) != 0 ||
	    fstat(src.fd, &src.st) != 0) {
		errf("cannot prepare the staged file (%s): %s",
		    strerror(errno), o.src);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}

	if ((rc = window_clear(&w)) != EX_HELPER_OK ||
	    (!o.new_node && (rc = target_clear(&t)) != EX_HELPER_OK)) {
		status = rc;
		goto cleanup;
	}
	if (renameatx_np(sdir, sleaf, w.fd, o.name,
	    o.new_node ? RENAME_EXCL : RENAME_SWAP) != 0) {
		errf("cannot put it in place (%s): %s/%s", strerror(errno),
		    o.parent, o.name);
		status = EX_HELPER_OPFAIL;
		goto cleanup;
	}
	moved = 1;
	/* The new file is at the name, and for a swap the sealed one is what
	 * went out; anything else is a race, put back as it was. */
	if (fstatat(w.fd, o.name, &chk, AT_SYMLINK_NOFOLLOW) != 0 ||
	    chk.st_ino != src.st.st_ino || (!o.new_node &&
	    (fstatat(sdir, sleaf, &out, AT_SYMLINK_NOFOLLOW) != 0 ||
	    out.st_ino != t.st.st_ino))) {
		if (o.new_node)
			rc = renameatx_np(w.fd, o.name, sdir, sleaf,
			    RENAME_EXCL);
		else
			rc = renameatx_np(sdir, sleaf, w.fd, o.name,
			    RENAME_SWAP);
		errf("refusing, the file at the name changed while it was "
		    "replaced%s: %s/%s", rc == 0 ? "" :
		    ", and could not be put back", o.parent, o.name);
		status = rc == 0 ? EX_HELPER_IDENT : EX_HELPER_OPFAIL;
		goto cleanup;
	}
	if (fchflags(src.fd, src.st.st_flags | flag) != 0) {
		errf("cannot seal it (%s): %s/%s", strerror(errno), o.parent,
		    o.name);
		fputs("window-open\t", stdout);
		print_escaped(t.path != NULL ? t.path : o.name);
		fputc('\n', stdout);
		status = EX_HELPER_WINOPEN;
	}
	/* The sealed file went out with its flags lifted; it leaves. */
	if (!o.new_node) {
		target_forget(&t);
		if (unlinkat(sdir, sleaf, 0) != 0)
			errf("cannot remove the replaced file from staging "
			    "(%s): %s", strerror(errno), o.src);
	}
	print_sum(hex, "");
	iset_add(&one, src.st.st_dev, src.st.st_ino);

cleanup:
	if (target_restore(&t, NULL) != 0)
		status = EX_HELPER_WINOPEN;
	if (window_restore(&w) != 0)
		status = EX_HELPER_WINOPEN;
	if (moved && status == EX_HELPER_OK &&
	    (w.saved & BLOCKING_FLAGS) != 0) {
		if (snapshot(w.fd, w.path, &w.after) != 0) {
			status = EX_HELPER_ANOMALY;
		} else {
			memset(&exp, 0, sizeof(exp));
			if (o.new_node) {
				exp.added = o.name;
				exp.add_dev = src.st.st_dev;
				exp.add_ino = src.st.st_ino;
			} else {
				exp.swapped = o.name;
				exp.swap_ino = src.st.st_ino;
			}
			if (diff_report(&w.before, &w.after, &exp) > 0)
				status = EX_HELPER_ANOMALY;
		}
	}
	if (status == EX_HELPER_OK || status == EX_HELPER_ANOMALY) {
		hits = writer_scan(&one);
		if (hits != 0)
			status = EX_HELPER_WRITER;
	}
	iset_free(&one);
	target_close(&t);
	window_close(&w);
	if (src.fd >= 0)
		close(src.fd);
	close(sdir);
	return (status);
}

/* ---- verb: digest ------------------------------------------------------- */

/* Every regular file under a held directory, depth first in name order --
 * the order seal_walk takes, so the two print the same lines. */
static int
digest_dir(const reader_t *r, const owners_t *owners, const node_t *dir,
    const char *path, const char *rel, dev_t dev, int depth, int inr)
{
	elist_t names;
	size_t i;
	char hex[65];
	int rc = EX_HELPER_OK;

	if (depth >= MAX_DEPTH) {
		errf("refusing a tree deeper than %d levels: %s", MAX_DEPTH,
		    path);
		return (EX_HELPER_REFUSED);
	}
	if (snapshot(dir->fd, path, &names) != 0)
		return (EX_HELPER_OPFAIL);
	for (i = 0; i < names.n && rc == EX_HELPER_OK; i++) {
		char *cpath = join_path(path, names.v[i].name);
		char *crel = rel_join(rel, names.v[i].name);
		int cinr = inr;
		node_t c;

		rc = node_at_as(dir->fd, names.v[i].name, cpath, &c, r, &cinr);
		become_self();
		if (rc == EX_HELPER_OK && c.st.st_dev != dev) {
			errf("refusing, a mount point inside the tree: %s",
			    cpath);
			rc = EX_HELPER_REFUSED;
		}
		if (rc == EX_HELPER_OK)
			rc = gate_owner(&c.st, cpath, owners);
		if (rc == EX_HELPER_OK && S_ISDIR(c.st.st_mode))
			rc = digest_dir(r, owners, &c, cpath, crel, dev,
			    depth + 1, cinr);
		else if (rc == EX_HELPER_OK && S_ISREG(c.st.st_mode)) {
			if (sha256_fd(c.fd, hex) != 0) {
				errf("cannot read (%s): %s", strerror(errno),
				    cpath);
				rc = EX_HELPER_OPFAIL;
			} else {
				print_sum(hex, crel);
			}
		}
		if (c.fd >= 0)
			close(c.fd);
		free(cpath);
		free(crel);
	}
	elist_free(&names);
	return (rc);
}

/*
 * digest: the fingerprint of the file at --src, or with --recursive of
 * every regular file in the folder there, in the lines seal --swap and
 * install print. Read as --as wherever --as owns the path, through the
 * owner gate, the top pinned by --src-id: what verify compares against the
 * fingerprints a seal recorded.
 */
static int
cmd_digest(int argc, char **argv)
{
	opts_t o;
	nodeid_t sid;
	owners_t owners;
	reader_t r;
	struct stat st;
	node_t top;
	char buf[PATH_MAX], hex[65];
	const char *leaf;
	int fd, pfd, inr = 1, rc;

	if (parse_opts(argc, argv, &o) != 0)
		return (EX_HELPER_USAGE);
	if (need_abs(o.src, "--src") != 0 ||
	    parse_ids(o.src_id, &sid, "--src-id") != 0 ||
	    parse_source(&o, &owners, &r) != 0)
		return (EX_HELPER_USAGE);

	if (!o.recursive) {
		rc = open_source(&o, &r, &owners, &sid, &fd, &st);
		if (rc != EX_HELPER_OK)
			return (rc);
		rc = sha256_fd(fd, hex);
		close(fd);
		if (rc != 0) {
			errf("cannot read (%s): %s", strerror(errno), o.src);
			return (EX_HELPER_OPFAIL);
		}
		print_sum(hex, "");
		return (EX_HELPER_OK);
	}
	pfd = open_parent(o.src, buf, sizeof(buf), &leaf, &r, &inr);
	if (pfd < 0) {
		become_self();
		return (pfd == -2 ? EX_HELPER_REFUSED : EX_HELPER_OPFAIL);
	}
	rc = node_at_as(pfd, leaf, o.src, &top, &r, &inr);
	become_self();
	close(pfd);
	if (rc != EX_HELPER_OK)
		return (rc);
	if (check_id("source", o.src, &sid, &top.st, at_fd(top.fd)) != 0)
		rc = EX_HELPER_IDENT;
	else if ((rc = gate_owner(&top.st, o.src, &owners)) == EX_HELPER_OK &&
	    !S_ISDIR(top.st.st_mode)) {
		errf("not a directory: %s", o.src);
		rc = EX_HELPER_OPFAIL;
	}
	if (rc == EX_HELPER_OK)
		rc = digest_dir(&r, &owners, &top, o.src, "", top.st.st_dev, 0,
		    inr);
	close(top.fd);
	return (rc);
}

/* ---- verb: mount -------------------------------------------------------- */

/*
 * The mount point of the volume a path resolves into: for a folder, the
 * folder itself; for anything else, its parent. A disk image attached over
 * a sealed folder, or over a folder above one, makes the path resolve into
 * the image, so its mount point is what this prints. Changes nothing and
 * needs no root, like `id`.
 */
static int
cmd_mount(int argc, char **argv)
{
	struct stat st;
	struct statfs sf;
	char buf[PATH_MAX], *slash;
	const char *q;

	if (argc != 3) {
		errf("mount takes exactly one path");
		return (EX_HELPER_USAGE);
	}
	if (need_abs(argv[2], "<path>") != 0)
		return (EX_HELPER_USAGE);
	q = argv[2];
	if (lstat(q, &st) != 0) {
		errf("cannot stat %s: %s", q, strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	if (!S_ISDIR(st.st_mode)) {
		if (strlcpy(buf, q, sizeof(buf)) >= sizeof(buf)) {
			errf("path too long: %s", q);
			return (EX_HELPER_USAGE);
		}
		slash = strrchr(buf, '/');
		if (slash == buf)
			slash[1] = '\0';
		else
			*slash = '\0';
		q = buf;
	}
	if (statfs(q, &sf) != 0) {
		errf("cannot read the volume of %s: %s", q, strerror(errno));
		return (EX_HELPER_OPFAIL);
	}
	print_escaped(sf.f_mntonname);
	fputc('\n', stdout);
	return (EX_HELPER_OK);
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

	/* What become_self() goes back to after a copy read as --as. */
	g_self_uid = geteuid();
	g_self_gid = getegid();

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
	/* Dispatched before the root gate: `id` and `mount` change nothing,
	 * and the bash side's unprivileged verbs need them. */
	if (strcmp(argv[1], "id") == 0 || strcmp(argv[1], "mount") == 0) {
		status = strcmp(argv[1], "id") == 0 ? cmd_id(argc, argv) :
		    cmd_mount(argc, argv);
		if (status == EX_HELPER_USAGE)
			usage();
		fflush(stdout);
		return (status);
	}

#ifndef LOCKED_HELPER_TEST
	if (geteuid() != 0) {
		errf("must run as root");
		return (EX_HELPER_USAGE);
	}
#endif

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
	else if (strcmp(argv[1], "copy-tree") == 0)
		status = cmd_copy_tree(argc, argv);
	else if (strcmp(argv[1], "seal") == 0)
		status = cmd_tree(argc, argv, 1);
	else if (strcmp(argv[1], "unseal") == 0)
		status = cmd_tree(argc, argv, 0);
	else if (strcmp(argv[1], "install") == 0)
		status = cmd_install(argc, argv);
	else if (strcmp(argv[1], "digest") == 0)
		status = cmd_digest(argc, argv);
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
