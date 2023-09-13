#include "../agent/udpctl.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define UDP_SOCKET_ADDREESS INADDR_ANY
#define UDP_SOCKET_PORT 10080

#define UNIX_SOCKET_PATH "/tmp/udpctl.sock"
#define IP_ADDRESS(A, B, C, D) (A * 0x1000000u + B * 0x10000 + C * 0x100 + D)

#define INPUT_BUFFER_LEN 256
#define RECV_BUFFER_LEN 256

struct sockaddr_in remote_address;
struct sockaddr_in local_address;

bool is_server = false;
short source_port = 0;
short ctl_level = 2;

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
    while ((opt = getopt(argc, argv, "lp:c:")) != -1) {
        switch (opt) {
            case 'l':
                is_server = 1;
                break;
            case 'p':
                source_port = atoi(optarg);
                printf("source_port = %d\n", source_port);
                break;
            case 'c':
                ctl_level = atoi(optarg);
                printf("ctl_level = %d\n", ctl_level);
                break;
            default:
                printf("Error! \'%c\' \'%c\'\n", opt, optopt);
                return 0;
        }
    }

    if (argc - optind == 2) { // Specified non-opt arguments for address and port

        // 名前解決
        struct addrinfo hints, *info;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        getaddrinfo(argv[optind], NULL, &hints, &info);
        struct in_addr resolved;
        resolved.s_addr = ((struct sockaddr_in *)(info->ai_addr))->sin_addr.s_addr;
        printf("Name resolution %s -> %s\n", argv[optind], inet_ntoa(resolved));

        // TODO for failure

        if(is_server){
            local_address.sin_addr.s_addr = resolved.s_addr;
            local_address.sin_port = htons(atoi(argv[optind+1]));
        }else{
            remote_address.sin_addr.s_addr = resolved.s_addr;
            remote_address.sin_port = htons(atoi(argv[optind+1]));
            printf("Target %s, %d\n", argv[optind], ntohs(remote_address.sin_port));
        }

    } else if (argc - optind == 1) { // Specified non-opt arguments only for port
        if(is_server){
            local_address.sin_addr.s_addr = INADDR_ANY;
            local_address.sin_port = htons(atoi(argv[optind]));
        } else { // If client mode, exit
            printf("Please specify address and port\n");
            exit(EXIT_FAILURE);
        }
    }else{
        printf("Invalid arguents\n");
        exit(EXIT_FAILURE);
    }

    if(is_server){
        printf("Runnning in server mode\n");
    }

    ssize_t	res;

    // UDP用ソケットの初期化
    udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // UDP用ソケットを開く
    if(udp_sock_fd < 0){
        perror("Failed to open socket for udp");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    if(is_server){ // If server mode
        bind_addr.sin_port = local_address.sin_port;
        bind_addr.sin_addr.s_addr = local_address.sin_addr.s_addr;
        res = bind(udp_sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)); // UDP用ソケットをbind
        if (res < 0) {
            perror("Failed to bind socket for udp");
            terminate(EXIT_FAILURE);
        }
        printf("Bound listen address\n");
    }else{ // If client mode
        if (source_port != 0) {
            bind_addr.sin_addr.s_addr = INADDR_ANY;
            bind_addr.sin_port = htons(source_port);
            res = bind(udp_sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)); // UDP用ソケットをbind
            if (res < 0) {
                perror("Failed to bind socket for udp");
                terminate(EXIT_FAILURE);
            }
            printf("Bound source address\n");
        }

    }

    printf("Succeed to open socket for udp (fd: %d)\n", udp_sock_fd);

    ssize_t len;
    struct sockaddr_un unix_addr{};

    // シグナルハンドラ
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
        perror("Failed to connect socket for ctl");
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

    printf("Succeeded to connect agent!\n");

    // 登録パケット
    uint8_t request_msg_buf[sizeof(udpctl_header) + sizeof(udpctl_request)];
    udpctl_header *request_msg_hdr;
    udpctl_request *request_msg_data;
    request_msg_hdr = reinterpret_cast<udpctl_header *>(request_msg_buf);
    request_msg_hdr->type = type_request;
    request_msg_hdr->length = sizeof(udpctl_request);
    request_msg_data = reinterpret_cast<udpctl_request *>(&request_msg_buf[sizeof(udpctl_header)]);
    request_msg_data->level = htons(ctl_level);

    res = send(un_fd, request_msg_data,
               sizeof(udpctl_header) + sizeof(udpctl_request), 0);

    if (res < 0) {
        perror("Failed to send request packet");
        terminate(res);
    }

    printf("Sent request %d!\n",ctl_level);

    fd_set sets, sets2;
    FD_ZERO(&sets);
    FD_ZERO(&sets2);
    FD_SET(udp_sock_fd, &sets);
    FD_SET(STDIN_FILENO, &sets);

    uint8_t inputs[INPUT_BUFFER_LEN];
    uint8_t input_len = 0;

    uint8_t recv_buffer[RECV_BUFFER_LEN];

    while(true){

        uint8_t keepalive_msg_buf[sizeof(udpctl_header)];
        udpctl_header *keepalive_header;
        keepalive_header = reinterpret_cast<udpctl_header *>(keepalive_msg_buf);
        keepalive_header->type = type_request;
        keepalive_header->length = 0;

        res = send(un_fd, keepalive_msg_buf, sizeof(udpctl_header), 0);
        if (res < 0) {
            perror("Failed to send");
            terminate(res);
        }
        printf("Sending keepalive\n");

        // 登録パケット
        uint8_t request_msg_buf[sizeof(udpctl_header) + sizeof(udpctl_request)];
        udpctl_header *request_msg_hdr;
        udpctl_request *request_msg_data;
        request_msg_hdr = reinterpret_cast<udpctl_header *>(request_msg_buf);
        request_msg_hdr->type = type_request;
        request_msg_hdr->length = sizeof(udpctl_request);
        request_msg_data = reinterpret_cast<udpctl_request *>(
            &request_msg_buf[sizeof(udpctl_header)]);
        request_msg_data->level = htons(ctl_level);

        res = send(un_fd, request_msg_data,
                   sizeof(udpctl_header) + sizeof(udpctl_request), 0);

        if (res < 0) {
            perror("Failed to send request packet");
            terminate(res);
        }

        printf("Sent request %d!\n", ctl_level);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        memcpy(&sets2, &sets, sizeof(sets));
        // printf("Selecting...\n");
        res = select(std::max(STDIN_FILENO, udp_sock_fd) + 1, &sets2, nullptr, nullptr, &tv);

        if (FD_ISSET(udp_sock_fd, &sets2)) {
            struct sockaddr_in recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            int recv_res = recvfrom(udp_sock_fd, &recv_buffer, RECV_BUFFER_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len); 
            if(recv_res < 0){
                perror("Failed to recv");
            }else{
                if(is_server && remote_address.sin_addr.s_addr == 0){
                    printf("Connection! %d\n", recv_res);
                    remote_address.sin_addr.s_addr = recv_addr.sin_addr.s_addr;
                    remote_address.sin_port = recv_addr.sin_port;
                }
                for(int i=0;i<recv_res;i++){
                    printf("%c", recv_buffer[i]);
                }
            }
        }

        if(FD_ISSET(STDIN_FILENO, &sets2)){
            int input = getchar();

            if (input_len < (INPUT_BUFFER_LEN - 1)) inputs[input_len++] = input;
            if (input == '\n') {
                if(is_server && remote_address.sin_addr.s_addr == 0){
                    printf("Connection is not ready\n");
                }else{
                    struct sockaddr_in send_addr;
                    send_addr.sin_family = AF_INET;
                    send_addr.sin_port = remote_address.sin_port;
                    send_addr.sin_addr.s_addr = remote_address.sin_addr.s_addr;

                    int send_res = sendto(udp_sock_fd, inputs, input_len, 0,
                                          (struct sockaddr *)&send_addr,
                                          sizeof(send_addr)); // 入力を送信!
                    if (send_res < 0) {
                        perror("Failed to send");
                    } else {
                        input_len = 0;
                    }
                }
            }
        }
       
        /*
        struct sockaddr_in server_addr, my_addr;
        socklen_t llen = sizeof(my_addr);
        getsockname(udp_sock_fd, (struct sockaddr *)&my_addr, &llen);
        printf("Port %d\n", ntohs(my_addr.sin_port));
        */
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
