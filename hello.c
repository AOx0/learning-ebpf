#include "hello.h"
#include "hello.skel.h"
#include <asm-generic/errno-base.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    if (level >= LIBBPF_DEBUG) {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {

    struct data_t *m = data;

    printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path,
           m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
    printf("Missed event\n");
}

int main() {
    struct hello_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    libbpf_set_print(libbpf_print_fn);

    skel = hello_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Fallo en cargarse el esqueleto\n");
        return 1;
    }

    struct bpf_map *conf = skel->maps.my_config;

    unsigned int key = 0;
    char message[12] = "Hello root ";
    err = bpf_map__update_elem(conf, &key, sizeof(key), &message, sizeof(message), 0);
    if (err) {
        fprintf(stderr, "Fallo en modificarse el mapa: %d\n", err);
        hello_bpf__destroy(skel);
        return 1;
    }
    

    err = hello_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Fallo en cargarse al kernel: %d\n", err);
        hello_bpf__destroy(skel);
        return 1;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Error al crear el perf buffer\n");
        hello_bpf__destroy(skel);
        return 1;
    }

    while (true) {
        err = perf_buffer__poll(pb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error al hacer poll: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
    hello_bpf__destroy(skel);
    
    return -err;
}

