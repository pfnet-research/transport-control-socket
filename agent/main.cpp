/**
 * Userspace program for PFN UDP research
 */
#include <cstdio>
#include <cstdint>
#include <cerrno>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <cstdlib>
#include <csignal>
#include <bpf/libbpf.h>



int main(){

    int map_fd = bpf_create_map_name(BPF_MAP_TYPE_ARRAY, "udp_port_data", sizeof(int), 4, 0xffff, 0);

    //bpf_create_map_name()

    if (map_fd < 0) {
        printf("Failed to create map '%s'\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    printf("Created map! %d\n", map_fd);

    int res_aaa = bpf_obj_pin(map_fd, "/sys/fs/bpf/udp");
    if(res_aaa < 0){
        printf("Failed to pin '%s'\n", strerror(errno));
    }

    for (int i=0; i<0xffff; i++){
        int value = 1010;
        int res = bpf_map_update_elem(map_fd, &i, &value, BPF_ANY);
        printf("Failed to set '%s'\n", strerror(errno));

        printf("%d\n", res);

    }


    while(true){
        sleep(1);
    }

    return 0;
}