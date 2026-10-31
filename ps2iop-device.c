/* -*-  mode:c; tab-width:8; c-basic-offset:8; indent-tabs-mode:nil;  -*- */
/*
 * The smb: device on the PS2 IOP, on top of usmb2.
 * Each share connected with SMB2_DEVCTL_CONNECT is the directory smb:/<name>.
 */
#include "errno.h"
#include <fcntl.h>
#include "iomanX.h"
#include "irx.h"
#include "loadcore.h"
#include "sysclib.h"
#include "thsemap.h"

#include "ps2iop-compat.h"
#include "ps2smb2.h"
#include "usmb2.h"

#define MODNAME "usmb2man"
#define VER_MAJOR 1
#define VER_MINOR 1

IRX_ID(MODNAME, VER_MAJOR, VER_MINOR);

#define STATUS_END_OF_FILE 0xC0000011

/* Largest READ or WRITE. usmb2 always asks for a credit charge of 1 */
#define MAX_IO 65536

struct share {
        struct share *next;
        char name[SMB2_MAX_NAME_LEN];
        struct usmb2_context *usmb2;
};

struct file {
        struct usmb2_context *usmb2;
        uint8_t *fid;
        uint32_t offset;
};

struct dir {
        struct usmb2_context *usmb2;
        uint8_t *dh;
        struct share *share; /* the next share to list, in smb:/ */
};

static struct share *shares;
static int sema;
static char path1[256], unc[256];
#ifdef USMB2_FEATURE_RENAME
static char path2[256];
#endif

static int smb_dummy(void)
{
        return -EIO;
}

#define lock() WaitSema(sema)
#define unlock() SignalSema(sema)

/*
 * Splits [/]<share>[/<path>] into the share's context and the path in it,
 * in buf and with backslashes. *rest is "" for the root of the share.
 */
static struct usmb2_context *lookup(const char *path, char *buf, char **rest)
{
        struct share *s;
        char *p;

        while (*path == '/') {
                path++;
        }
        if (strlen(path) >= sizeof(path1)) {
                return NULL;
        }
        strcpy(buf, path);
        p = strchr(buf, '/');
        if (p == NULL) {
                p = buf + strlen(buf);
        } else {
                *p++ = 0;
        }
        *rest = p;
        for (; *p; p++) {
                if (*p == '/') {
                        *p = '\\';
                }
        }
        while (p > *rest && p[-1] == '\\') {
                *--p = 0;
        }

        for (s = shares; s; s = s->next) {
                if (!strcmp(s->name, buf)) {
                        return s->usmb2;
                }
        }
        return NULL;
}

static int is_root(const char *path)
{
        while (*path == '/') {
                path++;
        }
        return *path == 0;
}

#ifdef HAVE_TIMESTAMPS
/*
 * FILETIME to the date in an iox_stat_t, to the minute: right from 2000 to
 * 2080. Without 64-bit division, which pulls in 3 KB of libgcc.
 */
static void filetime(const uint8_t *ft, unsigned char *t)
{
        static const uint8_t mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        uint64_t v;
        uint32_t mins, y, m, n;

        /* units of 6.7108864 seconds, since 2000-01-01 */
        memcpy(&v, ft, 8);
        n = (uint32_t)(v >> 26) - 1876228809;
        if (n > 0x7fffffff) {
                n = 0;
        }
        mins = ((uint64_t)n * 480383960) >> 32;

        n = mins / 1440;
        mins %= 1440;
        t[0] = 0;
        t[1] = 0;
        t[2] = mins % 60;
        t[3] = mins / 60;

        for (y = 2000; n >= (m = (y & 3) ? 365 : 366); y++) {
                n -= m;
        }
        for (m = 0; n >= (uint32_t)mdays[m] + (m == 1 && !(y & 3)); m++) {
                n -= mdays[m] + (m == 1 && !(y & 3));
        }
        t[4] = n + 1;
        t[5] = m + 1;
        t[6] = y;
        t[7] = y >> 8;
}
#else
/* Every file is from 2000-01-01 00:00 */
static void filetime(const uint8_t *ft, unsigned char *t)
{
        static const unsigned char d[8] = { 0, 0, 0, 0, 1, 1, 2000 & 0xff, 2000 >> 8 };

        memcpy(t, d, 8);
}
#endif /* HAVE_TIMESTAMPS */

/* times points to CreationTime, LastAccessTime and LastWriteTime */
static void fill_stat(iox_stat_t *st, const uint8_t *times, const uint8_t *size, uint8_t attr)
{
        memset(st, 0, sizeof(*st));
        st->mode = (attr & 0x10) ? FIO_S_IFDIR : FIO_S_IFREG;
        memcpy(&st->size, size, 4);
        memcpy(&st->hisize, size + 4, 4);
        filetime(times, st->ctime);
        filetime(times + 8, st->atime);
        filetime(times + 16, st->mtime);
}

static int smb_connect(smb2Connect_in_t *in)
{
        struct share *s;
        uint32_t ip = 0, n;
        char *p;
        int i;

        for (s = shares; s; s = s->next) {
                if (!strncmp(s->name, in->name, sizeof(s->name) - 1)) {
                        return -EEXIST;
                }
        }

        /* smb://a.b.c.d/share */
        if (strncmp(in->url, "smb://", 6)) {
                return -EINVAL;
        }
        p = in->url + 6;
        for (i = 0; i < 4; i++) {
                if (*p < '0' || *p > '9') {
                        return -EINVAL;
                }
                for (n = 0; *p >= '0' && *p <= '9'; p++) {
                        n = n * 10 + *p - '0';
                }
                if (n > 255 || *p++ != (i < 3 ? '.' : '/')) {
                        return -EINVAL;
                }
                ip |= n << (8 * i);
        }
        if (strlen(in->url) + 3 > sizeof(unc)) {
                return -EINVAL;
        }
        /* \\a.b.c.d\share */
        strcpy(unc, "\\\\");
        strcat(unc, in->url + 6);
        p = strchr(unc, '/');
        *p = '\\';
        p = strchr(p, '/');
        if (p) {
                *p = 0;
        }

        s = calloc(1, sizeof(*s));
        if (s == NULL) {
                return -ENOMEM;
        }
        strncpy(s->name, in->name, sizeof(s->name) - 1);
        s->usmb2 = usmb2_init_context(ip, in->username, in->password);
        if (s->usmb2 == NULL) {
                free(s);
                return -EIO;
        }
        if (usmb2_treeconnect(s->usmb2, unc)) {
                close(s->usmb2->fd);
                free(s->usmb2);
                free(s);
                return -EIO;
        }
        s->next = shares;
        shares = s;
        return 0;
}

static int smb_disconnect_all(void)
{
        struct share *s;

        while ((s = shares)) {
                shares = s->next;
                close(s->usmb2->fd);
                free(s->usmb2);
                free(s);
        }
        return 0;
}

static int smb_devctl(iop_file_t *f, const char *name, int cmd, void *arg,
                      unsigned int arglen, void *buf, unsigned int buflen)
{
        int rc = -EINVAL;

        lock();
        if (cmd == SMB2_DEVCTL_CONNECT) {
                rc = smb_connect(arg);
        } else if (cmd == SMB2_DEVCTL_DISCONNECT_ALL) {
                rc = smb_disconnect_all();
        }
        unlock();
        return rc;
}

static int smb_open(iop_file_t *f, const char *name, int flags, int mode)
{
        struct usmb2_context *u;
        struct file *file;
        char *p;
        int rc = 0;

        lock();
        u = lookup(name, path1, &p);
        if (u == NULL) {
                rc = -ENOENT;
                goto out;
        }
        file = calloc(1, sizeof(*file));
        if (file == NULL) {
                rc = -ENOMEM;
                goto out;
        }
        file->usmb2 = u;
        /* O_WRONLY or O_RDWR. usmb2_open(O_RDWR) creates the file if needed */
        if (flags & O_WRONLY) {
#if defined(USMB2_FEATURE_WRITE) && defined(USMB2_FEATURE_STAT) && defined(USMB2_FEATURE_UNLINK)
                uint8_t st[56];
                int exists;

                if (!(flags & O_CREAT) || (flags & O_EXCL)) {
                        exists = !usmb2_stat(u, p, st);
                        if (!exists && !(flags & O_CREAT)) {
                                rc = -ENOENT;
                        } else if (exists && (flags & O_EXCL)) {
                                rc = -EEXIST;
                        }
                }
                if (rc == 0 && (flags & O_TRUNC)) {
                        usmb2_unlink(u, p);
                }
                if (rc == 0) {
                        file->fid = usmb2_open(u, p, O_RDWR);
                }
#else
                rc = -EROFS;
#endif
        } else {
                file->fid = usmb2_open(u, p, O_RDONLY);
        }
        if (rc == 0 && file->fid == NULL) {
                rc = (flags & O_CREAT) ? -EIO : -ENOENT;
        }
        if (rc == 0 && (flags & O_APPEND)) {
                file->offset = usmb2_size(u, file->fid);
        }
        if (rc) {
                free(file->fid);
                free(file);
        } else {
                f->privdata = file;
        }
 out:
        unlock();
        return rc;
}

static int smb_close(iop_file_t *f)
{
        struct file *file = f->privdata;

        lock();
        usmb2_close(file->usmb2, file->fid);
        unlock();
#ifdef USMB2_FEATURE_CLOSE
        free(file->fid);
#endif
        free(file);
        return 0;
}

static int smb_rw(iop_file_t *f, uint8_t *buf, int size, int write)
{
        struct file *file = f->privdata;
        int32_t rc;
        int total = 0;

        lock();
        while (size > 0) {
                rc = size > MAX_IO ? MAX_IO : size;
                if (write) {
#ifdef USMB2_FEATURE_WRITE
                        rc = usmb2_pwrite(file->usmb2, file->fid, buf, rc, file->offset);
#else
                        rc = -1;
#endif
                } else {
                        rc = usmb2_pread(file->usmb2, file->fid, buf, rc, file->offset);
                }
                /* an NT status */
                if (rc < 0) {
                        if (total == 0 && rc != (int32_t)STATUS_END_OF_FILE) {
                                total = -EIO;
                        }
                        break;
                }
                if (rc == 0) {
                        break;
                }
                file->offset += rc;
                total += rc;
                buf += rc;
                size -= rc;
        }
        unlock();
        return total;
}

static int smb_read(iop_file_t *f, void *buf, int size)
{
        return smb_rw(f, buf, size, 0);
}

static int smb_write(iop_file_t *f, void *buf, int size)
{
        return smb_rw(f, buf, size, 1);
}

static int smb_lseek(iop_file_t *f, int offset, int whence)
{
        struct file *file = f->privdata;
        int size;

        if (whence == SEEK_CUR) {
                offset += file->offset;
        } else if (whence == SEEK_END) {
                lock();
                size = usmb2_size(file->usmb2, file->fid);
                unlock();
                if (size < 0) {
                        return -EIO;
                }
                offset += size;
        }
        if (offset < 0) {
                return -EINVAL;
        }
        file->offset = offset;
        return offset;
}

static s64 smb_lseek64(iop_file_t *f, s64 offset, int whence)
{
        return smb_lseek(f, offset, whence);
}

static int smb_dopen(iop_file_t *f, const char *name)
{
        struct usmb2_context *u;
        struct dir *dir;
        char *p;
        int rc = 0;

        dir = calloc(1, sizeof(*dir));
        if (dir == NULL) {
                return -ENOMEM;
        }
        lock();
        if (is_root(name)) {
                dir->share = shares;
        } else {
                u = lookup(name, path1, &p);
                if (u) {
                        dir->usmb2 = u;
                        dir->dh = usmb2_opendir(u, p);
                }
                if (dir->dh == NULL) {
                        rc = -ENOENT;
                }
        }
        unlock();
        if (rc) {
                free(dir);
        } else {
                f->privdata = dir;
        }
        return rc;
}

static int smb_dclose(iop_file_t *f)
{
        struct dir *dir = f->privdata;

        if (dir->dh) {
                lock();
                usmb2_closedir(dir->usmb2, dir->dh);
                unlock();
#ifdef USMB2_FEATURE_CLOSE
                free(dir->dh);
#endif
        }
        free(dir);
        return 0;
}

/*
 * A directory entry is [MS-FSCC] FileDirectoryInformation, with the name
 * as a nul-terminated string at 0x40
 */
static int smb_dread(iop_file_t *f, iox_dirent_t *de)
{
        struct dir *dir = f->privdata;
        uint8_t *e;

        if (dir->dh == NULL) {
                if (dir->share == NULL) {
                        return 0;
                }
                memset(&de->stat, 0, sizeof(de->stat));
                de->stat.mode = FIO_S_IFDIR;
                strcpy(de->name, dir->share->name);
                dir->share = dir->share->next;
                return 1;
        }

        lock();
        e = usmb2_readdir(dir->usmb2, dir->dh);
        unlock();
        if (e == NULL) {
                return 0;
        }
        fill_stat(&de->stat, &e[0x08], &e[0x28], e[0x38]);
        strncpy(de->name, (char *)&e[0x40], sizeof(de->name) - 1);
        de->name[sizeof(de->name) - 1] = 0;
        return 1;
}

#ifdef USMB2_FEATURE_STAT
/* st is [MS-FSCC] FileNetworkOpenInformation */
static int smb_getstat(iop_file_t *f, const char *name, iox_stat_t *stat)
{
        struct usmb2_context *u;
        uint8_t st[56];
        char *p;
        int rc = -ENOENT;

        if (is_root(name)) {
                memset(stat, 0, sizeof(*stat));
                stat->mode = FIO_S_IFDIR;
                return 0;
        }
        lock();
        u = lookup(name, path1, &p);
        if (u && usmb2_stat(u, p, st) == 0) {
                fill_stat(stat, &st[0x00], &st[0x28], st[0x30]);
                rc = 0;
        }
        unlock();
        return rc;
}
#else
#define smb_getstat smb_dummy
#endif

#ifdef USMB2_FEATURE_MKDIR
static int smb_mkdir(iop_file_t *f, const char *name, int mode)
{
        struct usmb2_context *u;
        char *p;
        int rc = -ENOENT;

        lock();
        u = lookup(name, path1, &p);
        if (u) {
                rc = usmb2_mkdir(u, p) ? -EIO : 0;
        }
        unlock();
        return rc;
}
#else
#define smb_mkdir smb_dummy
#endif

#ifdef USMB2_FEATURE_UNLINK
static int smb_delete(const char *name, int is_dir)
{
        struct usmb2_context *u;
        char *p;
        int rc = -ENOENT;

        lock();
        u = lookup(name, path1, &p);
        if (u) {
                rc = (is_dir ? usmb2_rmdir(u, p) : usmb2_unlink(u, p)) ? -EIO : 0;
        }
        unlock();
        return rc;
}

static int smb_remove(iop_file_t *f, const char *name)
{
        return smb_delete(name, 0);
}

static int smb_rmdir(iop_file_t *f, const char *name)
{
        return smb_delete(name, 1);
}
#else
#define smb_remove smb_dummy
#define smb_rmdir smb_dummy
#endif

#ifdef USMB2_FEATURE_RENAME
static int smb_rename(iop_file_t *f, const char *oldname, const char *newname)
{
        struct usmb2_context *u, *u2;
        char *p, *p2;
        int rc = -ENOENT;

        lock();
        u = lookup(oldname, path1, &p);
        u2 = lookup(newname, path2, &p2);
        if (u && u != u2) {
                rc = -EXDEV;
        } else if (u) {
                rc = usmb2_rename(u, p, p2) ? -EIO : 0;
        }
        unlock();
        return rc;
}
#else
#define smb_rename smb_dummy
#endif

static int smb_init(iop_device_t *dev)
{
        iop_sema_t s = { 0, 0, 1, 1 };

        sema = CreateSema(&s);
        return 0;
}

static int smb_deinit(iop_device_t *dev)
{
        smb_disconnect_all();
        DeleteSema(sema);
        return 0;
}

static iop_device_ops_t smb_ops = {
        &smb_init,
        &smb_deinit,
        (void *)&smb_dummy, /* format */
        &smb_open,
        &smb_close,
        &smb_read,
        &smb_write,
        &smb_lseek,
        (void *)&smb_dummy, /* ioctl */
        (void *)smb_remove,
        (void *)smb_mkdir,
        (void *)smb_rmdir,
        &smb_dopen,
        &smb_dclose,
        &smb_dread,
        (void *)smb_getstat,
        (void *)&smb_dummy, /* chstat */
        (void *)smb_rename,
        (void *)&smb_dummy, /* chdir */
        (void *)&smb_dummy, /* sync */
        (void *)&smb_dummy, /* mount */
        (void *)&smb_dummy, /* umount */
        &smb_lseek64,
        &smb_devctl,
        (void *)&smb_dummy, /* symlink */
        (void *)&smb_dummy, /* readlink */
        (void *)&smb_dummy  /* ioctl2 */
};

static iop_device_t smb_dev = {
        "smb",
        IOP_DT_FS | IOP_DT_FSEXT,
        1,
        "SMB2 on usmb2",
        &smb_ops
};

int _start(int argc, char *argv[])
{
        DelDrv(smb_dev.name);
        if (AddDrv(&smb_dev)) {
                return MODULE_NO_RESIDENT_END;
        }
        return MODULE_RESIDENT_END;
}
