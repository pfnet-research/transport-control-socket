#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <csignal>
#include <sys/socket.h>
#include <sys/un.h>

#include "udpctl.h"

#define UNIX_SOCKET_PATH "/tmp/udpctl.sock"
#define IP_ADDRESS(A, B, C, D) (A * 0x1000000u + B * 0x10000 + C * 0x100 + D)

int	un_fd = -1;

void terminate(int code){
    printf("Terminated (%d)\n", code);
    if(un_fd >= 0){
        shutdown(un_fd, SHUT_RDWR);
        close(un_fd);
    }
    exit(code);
}

[[noreturn]] int main(void) {

    ssize_t	res;
    ssize_t len;
    struct sockaddr_un unix_addr{};

    signal(SIGINT, terminate);
    signal(SIGTERM, terminate);

    un_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(un_fd < 0){
        perror("Failed to open socket");
        exit(EXIT_FAILURE);
    }

    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, UNIX_SOCKET_PATH);
    res = connect(un_fd, (struct sockaddr*)&unix_addr, sizeof(unix_addr));
    if(res < 0){
        perror("Failed to connect");
        terminate(EXIT_FAILURE);
    }
    printf("Succeed to connect\n");

    uint8_t open_msg_buf[sizeof(udpctl_header) + sizeof(udpctl_open)];
    udpctl_header *open_msg_hdr;
    udpctl_open *open_msg_data;
    open_msg_hdr = reinterpret_cast<udpctl_header*>(open_msg_buf);
    open_msg_hdr->type = type_open;
    open_msg_hdr->length = sizeof(udpctl_open);
    open_msg_data = reinterpret_cast<udpctl_open*>(&open_msg_buf[sizeof(udpctl_header)]);
    open_msg_data->version = UDPCTL_VERSION;
    memcpy(open_msg_data->magic, UDPCTL_MAGIC, 16);

    res = send(un_fd, open_msg_buf, sizeof(udpctl_header) + sizeof(udpctl_open), 0);

    if(res < 0){
        perror("Failed to send open packet");
        terminate(res);
    }

    uint8_t register_msg_buf[sizeof(udpctl_header) + sizeof(udpctl_register)];
    udpctl_header *register_msg_hdr;
    udpctl_register *register_msg_data;
    register_msg_hdr = reinterpret_cast<udpctl_header*>(register_msg_buf);
    register_msg_hdr->type = type_register;
    register_msg_hdr->length = sizeof(udpctl_register);
    register_msg_data = reinterpret_cast<udpctl_register*>(&register_msg_buf[sizeof(udpctl_header)]);
    register_msg_data->local_address = IP_ADDRESS(192, 168, 10, 1);
    register_msg_data->local_port = 19132;

    res = send(un_fd, register_msg_buf, sizeof(udpctl_header) + sizeof(udpctl_register), 0);

    if(res < 0){
        perror("Failed to send open packet");
        terminate(res);
    }

    while(true){
        uint8_t keepalive_msg_buf[sizeof(udpctl_header)];
        udpctl_header *keepalive_header;
        keepalive_header = reinterpret_cast<udpctl_header*>(keepalive_msg_buf);
        keepalive_header->type = type_keepalive;
        keepalive_header->length = 0;

        res = send(un_fd, keepalive_msg_buf, sizeof(udpctl_header), 0);
        if(res < 0){
            perror("Failed to send");
            terminate(res);
        }
        printf("Sending keepalive\n");

        sleep(5);
    }
    return 0;
}
