#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <csignal>
#include <cmath>
#include <cstdio>
#include <algorithm>
#include <sys/socket.h>
#include <sys/un.h>

#include "../agent/udpctl.h"

#define UDP_SOCKET_ADDREESS INADDR_ANY
#define UDP_SOCKET_PORT 10080

#define UNIX_SOCKET_PATH "/tmp/udpctl.sock"
#define IP_ADDRESS(A, B, C, D) (A * 0x1000000u + B * 0x10000 + C * 0x100 + D)

#define INPUT_BUFFER_LEN 256
#define RECV_BUFFER_LEN 256

bool is_server = false;

int udp_sock_fd = -1;
int	un_fd = -1;

void terminate(int code){
    printf("Terminated (%d)\n", code);
    if(un_fd >= 0){
        shutdown(un_fd, SHUT_RDWR);
        close(un_fd);
    }
    exit(code);
}

[[noreturn]] int main(int argc, char*argv[]) {

    // オプションのパース
    int opt;
    while ((opt = getopt(argc, argv, "l")) != -1) {
        switch (opt) {
            case 'l':
                is_server = 1;
                break;
            default:
                printf("Error! \'%c\' \'%c\'\n", opt, optopt);
                return 0;
        }
    }

    if(is_server){
        printf("Runnning in server mode\r\n");
    }

    ssize_t	res;

    // UDP用ソケットの初期化
    udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP用ソケットを開く
    if(udp_sock_fd < 0){
        perror("Failed to open socket for udp");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in udp_addr;
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_port = htons(UDP_SOCKET_PORT);
    udp_addr.sin_addr.s_addr = UDP_SOCKET_ADDREESS;

    res = bind(udp_sock_fd, (struct sockaddr *)&udp_addr, sizeof(udp_addr)); // UDP用ソケットをbind
    if(res < 0){
        perror("Failed to bind socket for udp");
        terminate(EXIT_FAILURE);
    }

    printf("Succeed to open socket for udp (fd: %d)\n", udp_sock_fd);

    ssize_t len;
    struct sockaddr_un unix_addr{};

    signal(SIGINT, terminate);
    signal(SIGTERM, terminate);

    // CTL用ソケットの初期化
    un_fd = socket(AF_UNIX, SOCK_STREAM, 0); // ctl用socket
    if(un_fd < 0){
        perror("Failed to open socket for ctl");
        exit(EXIT_FAILURE);
    }

    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, UNIX_SOCKET_PATH);
    res = connect(un_fd, (struct sockaddr*)&unix_addr, sizeof(unix_addr));
    if(res < 0){
        perror("Failed to connect");
        terminate(EXIT_FAILURE);
    }
    printf("Succeed to connect with unix domain socket (fd: %d)\n", un_fd);

    // Openパケット
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

    // 登録パケット
    uint8_t register_msg_buf[sizeof(udpctl_header) + sizeof(udpctl_register)];
    udpctl_header *register_msg_hdr;
    udpctl_register *register_msg_data;
    register_msg_hdr = reinterpret_cast<udpctl_header*>(register_msg_buf);
    register_msg_hdr->type = type_register;
    register_msg_hdr->length = sizeof(udpctl_register);
    register_msg_data = reinterpret_cast<udpctl_register*>(&register_msg_buf[sizeof(udpctl_header)]);
    register_msg_data->local_address = UDP_SOCKET_ADDREESS;
    register_msg_data->local_port = UDP_SOCKET_PORT;

    res = send(un_fd, register_msg_buf, sizeof(udpctl_header) + sizeof(udpctl_register), 0);

    if(res < 0){
        perror("Failed to send open packet");
        terminate(res);
    }

    fd_set sets, sets2;
    FD_ZERO(&sets);
    FD_ZERO(&sets2);
    FD_SET(STDIN_FILENO, &sets);
    FD_SET(udp_sock_fd, &sets);

    uint8_t aaa[1010];
    int laaab = 1010;
    int a = recv(udp_sock_fd, &aaa, laaab, 0);

    //printf("%d len\r\n", a);

    uint8_t inputs[INPUT_BUFFER_LEN];
    uint8_t input_len = 0;

    uint8_t recv_buffer[RECV_BUFFER_LEN];

    while(true){
        memcpy(&sets2, &sets, sizeof(sets));
        res = select(std::max(STDIN_FILENO, udp_sock_fd) + 1, &sets2, nullptr, nullptr, nullptr);

        if(FD_ISSET(STDIN_FILENO, &sets2)){
            int input;
            while(input = getchar()){
                if(input_len < (INPUT_BUFFER_LEN - 1)) inputs[input_len++] = input;
                if(input == '\n'){
                    struct sockaddr_in send_addr;
                    send_addr.sin_family = AF_INET;
                    send_addr.sin_port = htons(10000);
                    send_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

                    int send_res = sendto(udp_sock_fd, inputs, input_len, 0, (struct sockaddr *)&send_addr, sizeof(send_addr)); // 入力を送信!
                    if(send_res < 0){
                        perror("Failed to send");
                    }else{
                        input_len = 0;
                        printf("Send!\n");
                    }
                }
            }
        }

        if(FD_ISSET(udp_sock_fd, &sets2)){
            struct sockaddr_in recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            int recv_res = recvfrom(udp_sock_fd, &recv_buffer, RECV_BUFFER_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if(recv_res < 0){
                perror("Failed to recv");
            }else{
                for(int i=0;i<recv_res;i++){
                    printf("%c", recv_buffer[i]);
                }
            }

        }

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

        sleep(10);
    }
    // no return
}
