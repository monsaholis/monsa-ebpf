// MIT License
//
// Copyright (c) 2025 dev-monsa
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// User-space controller for cgroup_sock_addr example. Attaches all sock_addr
// hooks to a cgroup path and prints connect/bind/sendmsg counts.

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_cgroup_sock_addr.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: sudo %s <cgroup_path>\n", prog);
}

static int attach_all(struct example_cgroup_sock_addr_bpf *skel, int cg_fd, struct bpf_link **links)
{
    links[0] = bpf_program__attach_cgroup(skel->progs.msb_connect4, cg_fd);
    links[1] = bpf_program__attach_cgroup(skel->progs.msb_connect6, cg_fd);
    links[2] = bpf_program__attach_cgroup(skel->progs.msb_bind4, cg_fd);
    links[3] = bpf_program__attach_cgroup(skel->progs.msb_bind6, cg_fd);
    links[4] = bpf_program__attach_cgroup(skel->progs.msb_sendmsg4, cg_fd);
    links[5] = bpf_program__attach_cgroup(skel->progs.msb_sendmsg6, cg_fd);

    for (int i = 0; i < 6; i++) {
        if (!links[i])
            return -1;
    }
    return 0;
}

static void detach_all(struct bpf_link **links, int cnt)
{
    for (int i = 0; i < cnt; i++)
        bpf_link__destroy(links[i]);
}

static void print_stats(struct bpf_map *map)
{
    static const char *names[] = {"connect", "bind", "sendmsg"};
    __u32 key;
    __u64 value;
    int fd = bpf_map__fd(map);

    for (key = 0; key < 3; key++) {
        if (bpf_map_lookup_elem(fd, &key, &value) == 0)
            printf("%s count = %llu\n", names[key], (unsigned long long)value);
    }
}

int main(int argc, char **argv)
{
    const char *cg_path;
    int cg_fd = -1;
    struct example_cgroup_sock_addr_bpf *skel = NULL;
    struct bpf_link *links[6] = {0};
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    cg_path = argv[1];

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    cg_fd = open(cg_path, O_DIRECTORY | O_RDONLY);
    if (cg_fd < 0) {
        perror("open cgroup path");
        return 1;
    }

    skel = example_cgroup_sock_addr_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    if (attach_all(skel, cg_fd, links)) {
        fprintf(stderr, "failed to attach one of the sock_addr programs\n");
        err = 1;
        goto cleanup;
    }

    printf("Attached cgroup sock_addr hooks to %s. Ctrl+C to stop.\n", cg_path);
    while (!stop) {
        print_stats(skel->maps.sock_addr_counts);
        sleep(1);
    }

cleanup:
    detach_all(links, 6);
    example_cgroup_sock_addr_bpf__destroy(skel);
    if (cg_fd >= 0)
        close(cg_fd);
    return err ? 1 : 0;
}
