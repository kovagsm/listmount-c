#include <stdint.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/fcntl.h>
#include <cstdio>
#include <csignal>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>

#define SYS_statmount 457
#define SYS_listmount 458
#define LSMT_ROOT 0xffffffffffffffff

#define BUF_SIZE 255

int listmount(const struct mnt_id_req *req, uint64_t *mnt_ids, size_t nr_mnt_ids, unsigned long flags) {
    return syscall(SYS_listmount, req, mnt_ids, nr_mnt_ids, flags);
}

int statmount(const struct mnt_id_req *req, struct statmount *smbuf, size_t bufsize, unsigned long flags) {
    return syscall(SYS_statmount, req, smbuf, bufsize, flags);
}

struct linux_dirent64 {
    uint64_t       d_ino;
    uint64_t       d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

struct mnt_id_req {
    uint32_t size;        // sizeof(struct mnt_id_req)
    uint32_t spare;       // must be 0
    uint64_t mnt_id;      // mount ID to query
    uint64_t param;       // for statmount: mask; for listmount: last_mnt_id
};

struct statmount {
    uint32_t size;              // Total size, including strings
    uint32_t __spare1;
    uint64_t mask;              // What results were written
    uint32_t sb_dev_major;      // Device ID
    uint32_t sb_dev_minor;
    uint64_t sb_magic;          // ..._SUPER_MAGIC
    uint32_t sb_flags;          // SB_{RDONLY,SYNCHRONOUS,DIRSYNC,LAZYTIME}
    uint32_t fs_type;           // [str] Filesystem type
    uint64_t mnt_id;            // Unique ID of mount
    uint64_t mnt_parent_id;     // Unique ID of parent
    uint32_t mnt_id_old;        // Old IDs used in proc/.../mountinfo
    uint32_t mnt_parent_id_old;
    uint64_t mnt_attr;          // MOUNT_ATTR_...
    uint64_t mnt_propagation;   // MS_{SHARED,SLAVE,PRIVATE,UNBINDABLE}
    uint64_t mnt_peer_group;    // ID of shared peer group
    uint64_t mnt_master;        // Mount receives propagation from this ID
    uint64_t propagate_from;    // Propagation from in current namespace
    uint32_t mnt_root;          // [str] Root of mount relative to root of fs
    uint32_t mnt_point;         // [str] Mountpoint relative to current root
    uint64_t __spare2[50];
    char str[];                 // Variable size part containing strings
};

struct elem_list_data {
    uint64_t inode;
    int      nsfd;
};

struct elem_list {
    elem_list_data* elems;
    int             pos;
    int             size;
};

elem_list* elem_list_new(int size = 256) {
    elem_list * ret;
    ret = (elem_list*)malloc(sizeof(elem_list));
    ret->elems = (elem_list_data*)malloc(size * sizeof(elem_list_data));
    ret->size = size;
    ret->pos = 0;

    return ret;
}

void elem_list_del(elem_list *l) {
    free(l->elems);
    free(l);
}

void elem_list_add(elem_list *l, uint64_t inode, int fd) {
    if(l->pos == l->size) {
        l->size *= 2;
        (void)realloc(l->elems, l->size * sizeof(elem_list_data));
    }

    l->elems[l->pos].inode = inode;
    l->elems[l->pos].nsfd  = fd;
    l->pos++;
}

int elem_list_inode_exists(elem_list *l, uint64_t inode) {
    int i = 0;
    for(; i!= l->pos; ++i) {
        if (l->elems[i].inode == inode) {
            return 1;
        }
    }
    return 0;
}

int isnum(char * s) {
    while (*s != 0) {
        if (*s < '0' || *s > '9') {
            return 0;
        }
        s++;
    }
    return 1;
}

void mntnspath(char* buf, char* pid) {
    const char *prefix = "/proc/";
    const char *suffix = "/ns/mnt";

    // Copy prefix
    while (*prefix) {
        *buf++ = *prefix++;
    }
    // Copy pid
    while (*pid) {
        *buf++ = *pid++;
    }
    // Copy suffix
    while (*suffix) {
        *buf++ = *suffix++;
    }
    // Null-terminate the buffer
    *buf = '\0';
}

uint64_t get_inode_from_path(char *path) {
    //printf("getting inode from path: %s\n", path);
    int r;
    struct stat statbuf;
    r = stat(path, &statbuf);
    if (r == 0) {
        return statbuf.st_ino;
    } else {
        printf("error: %d\n", r);
    }
    return 0;
}

void list_mounts_for_ns(int fd) {
    int res = setns(fd, 0);
    if (res != 0) {
        printf("Error setting namespace: %d\n", res);
        return;
    }
    struct mnt_id_req listReq = {
            .size = sizeof(struct mnt_id_req),
            .spare = 0,
            .mnt_id = LSMT_ROOT,
            .param = 0
    };

    uint64_t mnt_ids[BUF_SIZE];
    int ret = listmount(&listReq, mnt_ids, BUF_SIZE, 0);
    if (ret < 0) {
        printf("listmount failed: %d\n", errno);
        return;
    }

    for(int i = 0; i != ret; ++i) {
        printf("Mount found: %u\n", mnt_ids[i]);
    }

}

void list_all_proc(char * proc = "/proc") {
    elem_list* e = elem_list_new();

    int fd = syscall(SYS_open, proc, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    char buf[BUF_SIZE];
    int nread;

    mntnspath(buf, "self");

    while ((nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE)) > 0) {
        for (int bpos = 0; bpos < nread; ) {
            struct linux_dirent64 *d = (struct linux_dirent64 *)(buf + bpos);
            if (d->d_type == DT_DIR && isnum(d->d_name)) {
                char path[255];
                mntnspath(path, d->d_name);

                uint64_t mnt_ns = get_inode_from_path(path);
                if (!elem_list_inode_exists(e, mnt_ns)) {
                    int fd = open(path, O_RDONLY | O_CLOEXEC);
                    elem_list_add(e, mnt_ns, fd);
                }
            }
            bpos += d->d_reclen;
        }
    }

    int i = 0;
    for(; i != e->pos; ++i) {
        printf("Listing mounts for ns: %u\n", e->elems[i].inode);
        list_mounts_for_ns(e->elems[i].nsfd);
        close(e->elems[i].nsfd);
    }

    elem_list_del(e);
}


int main() {
    list_all_proc();
}
