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

#include "../agent/ctrl_sock.h"

/* Sample netcat application*/

#define UDP_SOCKET_ADDREESS INADDR_ANY
#define UDP_SOCKET_PORT 10080

#define IP_ADDRESS(A, B, C, D) (A * 0x1000000u + B * 0x10000 + C * 0x100 + D)

#define INPUT_BUFFER_LEN 256
#define RECV_BUFFER_LEN 256

struct sockaddr_in remote_address;
struct sockaddr_in local_address;

bool is_server = false;
short source_port = 0;
short ctl_level = 2;

int udp_sock_fd = -1;  // fd for udp socket
int ctrl_sock_fd = -1; // fd for control socket

// Buffer for control socket
uint8_t ctrl_sock_buffer[MAX_MESSAGE_SIZE + 1];
uint16_t ctrl_sock_rcvd_size = 0;

void terminate(int code) {
    printf("terminated (%d)\n", code);
    if (ctrl_sock_fd >= 0) {
        shutdown(ctrl_sock_fd, SHUT_RDWR);
        close(ctrl_sock_fd);
    }
    exit(code);
}

int handle_ctrl_message(msg_header *hdr, ssize_t len);

[[noreturn]] int main(int argc, char *argv[]) {

    // Parsing options
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
            printf("error! \'%c\' \'%c\'\n", opt, optopt);
            terminate(EXIT_FAILURE);
        }
    }

    if (argc - optind == 2) { // Specified non-opt arguments for address and port

        // Name resolution
        struct addrinfo hints, *info;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        getaddrinfo(argv[optind], NULL, &hints, &info);
        struct in_addr resolved;
        resolved.s_addr = ((struct sockaddr_in *)(info->ai_addr))->sin_addr.s_addr;
        printf("name resolution (%s -> %s)\n", argv[optind], inet_ntoa(resolved));

        // TODO: for failure

        if (is_server) {
            local_address.sin_addr.s_addr = resolved.s_addr;
            local_address.sin_port = htons(atoi(argv[optind + 1]));
        } else {
            remote_address.sin_addr.s_addr = resolved.s_addr;
            remote_address.sin_port = htons(atoi(argv[optind + 1]));
            printf("target %s:%d\n", inet_ntoa(resolved), ntohs(remote_address.sin_port));
        }

    } else if (argc - optind == 1) { // Specified non-opt arguments only for port
        if (is_server) {
            local_address.sin_addr.s_addr = INADDR_ANY;
            local_address.sin_port = htons(atoi(argv[optind]));
        } else { // If client mode, exit
            printf("please specify address and port\n");
            exit(EXIT_FAILURE);
        }
    } else {
        printf("invalid arguents\n");
        exit(EXIT_FAILURE);
    }

    if (is_server) {
        printf("runnning in server mode\n");
    }

    ssize_t res;

    /** Initialize udp socket **/

    udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0); // Try to open udp socket
    if (udp_sock_fd < 0) {
        perror("failed to open udp socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in bind_addr;
    bind_addr.sin_family = AF_INET;
    if (is_server) { // If server mode
        bind_addr.sin_port = local_address.sin_port;
        bind_addr.sin_addr.s_addr = local_address.sin_addr.s_addr;
        res = bind(udp_sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)); // Try to bind
        if (res < 0) {
            perror("failed to bind udp socket");
            terminate(EXIT_FAILURE);
        }
        printf("bound listen address\n");
    } else { // If client mode
        if (source_port != 0) {
            bind_addr.sin_addr.s_addr = INADDR_ANY;
            bind_addr.sin_port = htons(source_port);
            res = bind(udp_sock_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)); // UDP用ソケットをbind
            if (res < 0) {
                perror("failed to bind udp socket");
                terminate(EXIT_FAILURE);
            }
            printf("bound source address\n");
        }
    }

    printf("succeed to open udp socket (fd: %d)\n", udp_sock_fd);

    ssize_t len;
    struct sockaddr_un unix_addr {};

    // Configure signal handler
    signal(SIGINT, terminate);
    signal(SIGTERM, terminate);

    /** Initialize control socket **/

    ctrl_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0); // Open control socket
    if (ctrl_sock_fd < 0) {
        perror("failed to open ctrl socket");
        exit(EXIT_FAILURE);
    }

    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, CTRL_SOCKET_PATH);
    res = connect(ctrl_sock_fd, (struct sockaddr *)&unix_addr, sizeof(unix_addr));
    if (res < 0) {
        perror("failed to connect ctrl socket");
        terminate(EXIT_FAILURE);
    }
    printf("succeed to connect to ctrl socket (fd: %d)\n", ctrl_sock_fd);

    // Sending open message to ctrl socket
    msg_open *open_msg_buf;
    open_msg_buf = (msg_open *)malloc(sizeof(msg_open));

    open_msg_buf->hdr.length = sizeof(msg_open);
    open_msg_buf->hdr.type = TYPE_OPEN;

    res = send(ctrl_sock_fd, open_msg_buf, sizeof(msg_open), 0);

    free(open_msg_buf);

    if (res < 0) {
        perror("failed to send open message");
        terminate(res);
    }

    // Sending check message to ctrl socket
    msg_ctrl_test_con *test_msg_buf;
    test_msg_buf = (msg_ctrl_test_con *)malloc(sizeof(msg_ctrl_test_con));

    test_msg_buf->hdr.length = sizeof(msg_ctrl_test_con);
    test_msg_buf->hdr.type = TYPE_CTRL_TEST_CONNECTION;
    test_msg_buf->test_num = htonl(0x984321);

    res = send(ctrl_sock_fd, test_msg_buf, sizeof(msg_ctrl_test_con), 0);

    free(test_msg_buf);

    if (res < 0) {
        perror("failed to send check message");
        terminate(res);
    }

    printf("testing to connect agent\n");

    fd_set sets, sets2;
    FD_ZERO(&sets);
    FD_ZERO(&sets2);
    FD_SET(udp_sock_fd, &sets);
    FD_SET(ctrl_sock_fd, &sets);
    FD_SET(STDIN_FILENO, &sets);

    uint8_t inputs[INPUT_BUFFER_LEN];
    uint8_t input_len = 0;

    uint8_t recv_buffer[RECV_BUFFER_LEN];

    while (true) {

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        memcpy(&sets2, &sets, sizeof(sets));
        // printf("Selecting...\n");
        res = select(std::max(STDIN_FILENO, std::max(ctrl_sock_fd, udp_sock_fd)) + 1, &sets2, nullptr, nullptr, &tv);

        if (FD_ISSET(udp_sock_fd, &sets2)) { // Received something from udp socket
            struct sockaddr_in recv_addr;
            socklen_t recv_addr_len = sizeof(recv_addr);
            int recv_res = recvfrom(udp_sock_fd, &recv_buffer, RECV_BUFFER_LEN, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (recv_res < 0) {
                perror("failed to recv");
            } else {
                if (is_server && remote_address.sin_addr.s_addr == 0) {
                    printf("connection! %d\n", recv_res);
                    remote_address.sin_addr.s_addr = recv_addr.sin_addr.s_addr;
                    remote_address.sin_port = recv_addr.sin_port;
                }
                for (int i = 0; i < recv_res; i++) {
                    printf("%c", recv_buffer[i]);
                }
            }
        }

        msg_header *hdr_ptr;

        if (FD_ISSET(ctrl_sock_fd, &sets2)) { // Received something from control socket
            printf("received message from ctrl socket\n");
            if (ctrl_sock_rcvd_size < sizeof(msg_header)) {                                                                    // まだヘッダも受信できてない場合
                len = recv(ctrl_sock_fd, &ctrl_sock_buffer[ctrl_sock_rcvd_size], sizeof(msg_header) - ctrl_sock_rcvd_size, 0); // ひとまずヘッダを受信する
            } else {                                                                                                           // ヘッダは受信できているとき
                hdr_ptr = (msg_header *)&ctrl_sock_buffer;
                len = recv(ctrl_sock_fd, &ctrl_sock_buffer[ctrl_sock_rcvd_size], hdr_ptr->length - ctrl_sock_rcvd_size, 0);
            }

            if (len < 0) { // Failure
                perror("failed to recv");
                terminate(EXIT_FAILURE);
            } else if (len == 0) { // Close connection
                printf("closed control socket by agent\n");
                terminate(EXIT_FAILURE);
            } else { // 正常に受信できたら
                ctrl_sock_rcvd_size += len;
                // printf("size: %d\n", ctrl_sock_rcvd_size);
                if (ctrl_sock_rcvd_size >= sizeof(msg_header)) { // ヘッダを受信できている場合
                    hdr_ptr = (msg_header *)&ctrl_sock_buffer;
                    if (hdr_ptr->length == ctrl_sock_rcvd_size) { // ヘッダに書かれているメッセージサイズと受信済みのサイズが等しいとき
                        handle_ctrl_message(hdr_ptr, len);        // メッセージの処理に送る

                        ctrl_sock_rcvd_size = 0;
                    } else if (hdr_ptr->length > ctrl_sock_rcvd_size) { // まだ足りないとき
                                                                        // 次のループでチャレンジ
                    } else {                                            // 大きすぎるとき(バグ以外では発生しない)
                        fprintf(stderr, "received message is too large\n");
                        terminate(EXIT_FAILURE);
                    }
                }
            }
        }

        if (FD_ISSET(STDIN_FILENO, &sets2)) { // Received something from stdin
            int input = getchar();

            if (input_len < (INPUT_BUFFER_LEN - 1))
                inputs[input_len++] = input;
            if (input == '\n') {
                if (is_server && remote_address.sin_addr.s_addr == 0) {
                    printf("connection is not ready\n");
                } else {
                    struct sockaddr_in send_addr;
                    send_addr.sin_family = AF_INET;
                    send_addr.sin_port = remote_address.sin_port;
                    send_addr.sin_addr.s_addr = remote_address.sin_addr.s_addr;

                    int send_res = sendto(udp_sock_fd, inputs, input_len, 0, (struct sockaddr *)&send_addr,
                                          sizeof(send_addr)); // 入力を送信!
                    if (send_res < 0) {
                        perror("failed to send");
                    } else {
                        input_len = 0;
                    }
                }
            }
        }
    }

    // no return
}

int send_ctrl_set_opt_exp() {
    msg_ctrl_set_opt_exp *msg_ptr = (msg_ctrl_set_opt_exp *)malloc(sizeof(msg_ctrl_set_opt_exp));

    msg_ptr->hdr.length = sizeof(msg_ctrl_set_opt_exp);
    msg_ptr->hdr.type = TYPE_CTRL_SET_OPTION_EXPERIMENTAL;
    msg_ptr->set_type = SET_TYPE_COUNT(30000);
    msg_ptr->value = 10000;
    msg_ptr->flow.prefix = 0;
    msg_ptr->flow.netmask = 0;
    msg_ptr->flow.src_port = 0;
    msg_ptr->flow.dst_port = 0;

    send(ctrl_sock_fd, msg_ptr, sizeof(msg_ctrl_set_opt_exp), 0);

    free(msg_ptr);

    return 0;
}

int handle_ctrl_message(msg_header *hdr, ssize_t len) {
    switch (hdr->type) {
    case TYPE_NOTIFY_TEST_CONNECTION_REPLY:
        send_ctrl_set_opt_exp();
        printf("success to connect agent test\n");
        break;
    }
    return 0;
}