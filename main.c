#include <stdint.h>
#include <stdlib.h>
#include <syscall.h>
#include <sys/fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sched.h>
#include "string.h"
#include <errno.h>

#define SYS_statmount 457
#define SYS_listmount 458
#define LSMT_ROOT 0xffffffffffffffff

#define BUF_SIZE 255

#define STATMOUNT_SB_BASIC       0x00000001U
#define STATMOUNT_MNT_BASIC      0x00000002U
#define STATMOUNT_PROPAGATE_FROM 0x00000004U
#define STATMOUNT_MNT_ROOT       0x00000008U
#define STATMOUNT_MNT_POINT      0x00000010U
#define STATMOUNT_FS_TYPE        0x00000020U

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
    struct elem_list_data* elems;
    int             pos;
    int             size;
};

struct elem_list* elem_list_new(int size) {
    struct elem_list * ret;
    ret = (struct elem_list*)malloc(sizeof(struct elem_list));
    ret->elems = (struct elem_list_data*)malloc(size * sizeof(struct elem_list_data));
    ret->size = size;
    ret->pos = 0;

    return ret;
}

void elem_list_del(struct elem_list *l) {
    free(l->elems);
    free(l);
}

void elem_list_add(struct elem_list *l, uint64_t inode, int fd) {
    if(l->pos == l->size) {
        l->size *= 2;
        (void)realloc(l->elems, l->size * sizeof(struct elem_list_data));
    }

    l->elems[l->pos].inode = inode;
    l->elems[l->pos].nsfd  = fd;
    l->pos++;
}

int elem_list_inode_exists(struct elem_list *l, uint64_t inode) {
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

void print_stat(struct statmount* sm) {
    // Super block basic info
    if (sm->sb_flags & STATMOUNT_SB_BASIC) {
        printf("=== Super Block Info ===\n");
        printf("Device: %d : %d\n", sm->sb_dev_major, sm->sb_dev_minor);
        printf("Magic: %d\n", sm->sb_magic);
        printf("Flags: %d\n", sm->sb_flags);
    }

    if (sm->mask & STATMOUNT_MNT_BASIC) {
        printf("=== Mount Info ===\n");
        printf("Mount ID (unique): %llu\n", sm->mnt_id);
        printf("Mount ID (old): %u\n", sm->mnt_id_old);
        printf("Parent ID (unique): %llu\n", sm->mnt_parent_id);
        printf("Parent ID (old): %u\n", sm->mnt_parent_id_old);
        printf("Mount attributes: %llu\n", sm->mnt_attr);
        printf("Propagation flags: %llu\n", sm->mnt_propagation);
        printf("Peer group: %llu\n", sm->mnt_peer_group);
        printf("Master: %llu\n", sm->mnt_master);
    }

    if (sm->mask & STATMOUNT_PROPAGATE_FROM) {
        printf("=== Propagation Info ===\n");
        printf("Propagate from: %llu\n", sm->propagate_from);
    }

    printf("=== Paths and Types ===\n");

    if (sm->mask & STATMOUNT_MNT_POINT) {
        printf("Mount point: %s\n", (sm->str + sm->mnt_point));
    }

    if (sm->mask & STATMOUNT_MNT_ROOT) {
        printf("Mount root: %s\n", (sm->str + sm->mnt_root));
    }

    if (sm->mask & STATMOUNT_FS_TYPE) {
        printf("Filesystem type: %s\n", (sm->str + sm->fs_type));
    }
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

    const size_t stat_bufsize = 4096;  // Large enough for strings
    char *stat_buffer = malloc(sizeof(char) * stat_bufsize);
    struct statmount *sm = (struct statmount *)stat_buffer;

    for(int i = 0; i != ret; ++i) {
        printf("Mount found: %llu\n", mnt_ids[i]);
        struct mnt_id_req statReq = {
                .size = sizeof(struct mnt_id_req),
                .spare = 0,
                .mnt_id = mnt_ids[i],
                .param = STATMOUNT_SB_BASIC
                         | STATMOUNT_MNT_BASIC
                         | STATMOUNT_PROPAGATE_FROM
                         | STATMOUNT_MNT_ROOT
                         | STATMOUNT_MNT_POINT
                         | STATMOUNT_FS_TYPE
        };

        memset(stat_buffer, 0, stat_bufsize);
        auto sret = statmount(&statReq, sm, stat_bufsize, 0);

        if (sret < 0) {
            printf("statmount failed\n");
            continue;
        }

        print_stat(sm);
    }

    free(stat_buffer);

}

void list_all_proc(char * proc) {
    if(proc == NULL) {
       proc = "/proc";
    }
    struct elem_list* e = elem_list_new(256);

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
    list_all_proc(NULL);
}
