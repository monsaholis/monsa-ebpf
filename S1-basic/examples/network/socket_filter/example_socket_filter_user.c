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

// User-space controller for the classic socket filter example. Attaches the
// filter to a raw packet socket and prints packet counts.

#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_socket_filter.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: sudo %s <ifname>\n", prog);
}

static void print_stats(struct bpf_map *map)
{
    __u32 key = 0;
    __u64 values[128];
    __u64 total = 0;
    int fd = bpf_map__fd(map);
    unsigned int i, num_cpus = libbpf_num_possible_cpus();

    if (num_cpus > 128)
        num_cpus = 128;

    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (i = 0; i < num_cpus; i++)
            total += values[i];
        printf("socket packets = %llu\n", (unsigned long long)total);
    }
}

int main(int argc, char **argv)
{
    const char *ifname;
    int ifindex;
    int sock_fd = -1;
    struct sockaddr_ll sll = {0};
    struct example_socket_filter_bpf *skel = NULL;
    int prog_fd;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = example_socket_filter_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket");
        err = 1;
        goto cleanup;
    }

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        err = 1;
        goto cleanup;
    }

    prog_fd = bpf_program__fd(skel->progs.msb_socket_filter);
    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("SO_ATTACH_BPF");
        err = 1;
        goto cleanup;
    }

    printf("Attached socket filter to %s. Ctrl+C to stop.\n", ifname);
    while (!stop) {
        print_stats(skel->maps.socket_stats);
        sleep(1);
    }

cleanup:
    if (sock_fd >= 0)
        close(sock_fd);
    example_socket_filter_bpf__destroy(skel);
    return err ? 1 : 0;
}
