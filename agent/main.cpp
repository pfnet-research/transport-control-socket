/**
 * Userspace program for PFN UDP research
 */
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>

#include "../agent/udpctl.h"
#include "../bpf/udpbpf.h"

#define UNIX_SOCKET_PATH "/tmp/udpctl.sock"
#define MAX_CONNECTION 10

int map_fd;

enum class connection_type { closed, open, registered };

struct connection_state {
    int fd;
    connection_type type;
    uint32_t local_address;
    uint16_t local_port;
};

connection_state states[MAX_CONNECTION];

void terminate(int code) {
    // printf("Terminated (%d)\n", code);
    unlink(UNIX_SOCKET_PATH);
    exit(code);
}

int handle_udpctl_packet(connection_state *state, udpctl_header *hdr,
                         ssize_t len) {
    printf("Handle packet type %d from %d\n", hdr->type, state->fd);

    switch (hdr->type) {
        case udpctl_type::type_open: {
            if (state->type != connection_type::closed)
                return 1; // 新規のコネクションでなかったらエラー
            if (len != sizeof(udpctl_header) + sizeof(udpctl_open)) return 1;
            udpctl_open *open_msg;
            open_msg = reinterpret_cast<udpctl_open *>(hdr + 1);
            if (open_msg->version != UDPCTL_VERSION) {
                printf("Invalid version %d\n", open_msg->version);
                return 1;
            }
            if (memcmp(open_msg->magic, UDPCTL_MAGIC, 16) != 0) {
                printf("Invalid magic %d\n", open_msg->version);
                return 1;
            }
            state->type = connection_type::open;
            printf("Connection open (%d) version %d\n", state->fd,
                   open_msg->version);
        } break;
        case type_register: {
            if (state->type != connection_type::open) return 1;
            if (len != sizeof(udpctl_header) + sizeof(udpctl_register))
                return 1;
            udpctl_register *register_msg;
            register_msg = reinterpret_cast<udpctl_register *>(hdr + 1);

            state->local_address = register_msg->local_address;
            state->local_port = register_msg->local_port;

            state->type = connection_type::registered;
            printf("Connection registered (%d) address %s, port %d\n",
                   state->fd,
                   inet_ntoa(
                       in_addr{.s_addr = htonl(register_msg->local_address)}),
                   register_msg->local_port);
        } break;
        case type_keepalive:
            if (state->type != connection_type::registered) return 1;
            printf("Keepalive (fd: %d)\n", state->fd);
            break;
        case type_request:
            if (state->type != connection_type::registered) return 1;
            udpctl_request *request_msg;
            request_msg = reinterpret_cast<udpctl_request *>(hdr + 1);

            printf("Received request (fd: %d)\n", state->fd);

            struct key intert_key = {.local_address = htonl(state->local_address),
                                     .local_port = htons(state->local_port)};

            int res = bpf_map_update_elem(map_fd, &intert_key, &request_msg->level, BPF_ANY);
            if (res < 0) {
                printf("Failed to update intent '%s'\n", strerror(errno));
                printf("%d\n", res);
                terminate(-1);
            }
            break;
    }

    return 0;
}

[[noreturn]] void run_agent() {
    int fd_accept, max_fd;

    fd_accept = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_accept < 0) {
        perror("Failed to open socket");
        exit(EXIT_FAILURE);
    }
    max_fd = fd_accept;

    struct sockaddr_un sun = {};
    socklen_t sun_len;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, UNIX_SOCKET_PATH);
    sun_len = sizeof(sun);

    int res;

    res = bind(fd_accept, (struct sockaddr *)&sun, sun_len);
    if (res < 0) {
        perror("Failed to bind address");
        shutdown(fd_accept, SHUT_RDWR);
        close(fd_accept);
        unlink(UNIX_SOCKET_PATH);
        exit(EXIT_FAILURE);
    }

    res = listen(fd_accept, MAX_CONNECTION);
    if (res < 0) {
        perror("Failed to listen");
        shutdown(fd_accept, SHUT_RDWR);
        close(fd_accept);
        unlink(UNIX_SOCKET_PATH);
        exit(EXIT_FAILURE);
    }

    fd_set sets, sets2; // 更新用, つかう用
    FD_ZERO(&sets);
    FD_ZERO(&sets2);
    FD_SET(fd_accept, &sets);
    FD_SET(STDIN_FILENO, &sets);

    for (int i = 0; i < MAX_CONNECTION; i++) {
        states[i].fd = -1;
        states[i].type = connection_type::closed;
    }

    int new_fd;
    ssize_t len, add_len;
    uint8_t buf[2000];
    udpctl_header *hdr_ptr;

    while (true) {
        memcpy(&sets2, &sets, sizeof(sets));
        res = select(max_fd + 1, &sets2, nullptr, nullptr, nullptr);
        if (res < 0) {
            perror("Failed to select");
        }
        if (FD_ISSET(STDIN_FILENO, &sets2)) {
            int input = getchar();
            if (input == 's') {
                printf("\nShow states\n");
                for (int i = 0; i < MAX_CONNECTION; i++) {
                    printf("fd %d state %d ", states[i].fd, states[i].type);
                    switch (states[i].type) {
                        case connection_type::registered:
                            printf(
                                "address %s port %d\n",
                                inet_ntoa(in_addr{
                                    .s_addr = htonl(states[i].local_address)}),
                                states[i].local_port);
                            break;
                        default:
                            printf("\n");
                            break;
                    }
                }
            }
        }
        if (FD_ISSET(fd_accept, &sets2)) { // accept用のディスクリプタが何か受信していたら
            new_fd = accept(fd_accept, (struct sockaddr *)&sun, &sun_len);
            if (new_fd < 0) {
                perror("Failed to accept");
                unlink(UNIX_SOCKET_PATH);
                exit(EXIT_FAILURE);
            }
            printf("New accept (%d).\n", new_fd);

            for (int i = 0; i < MAX_CONNECTION; i++) {
                if (states[i].fd == -1) {
                    states[i].fd = new_fd;
                    break;
                }
                if (i == MAX_CONNECTION - 1) {
                    fprintf(stderr, "Already connected max connections\n");
                    exit(EXIT_FAILURE);
                }
            }
            FD_SET(new_fd, &sets);
            if (new_fd > max_fd) {
                max_fd = new_fd;
            }
        }
        for (int i = 0; i < MAX_CONNECTION; i++) {
            if (states[i].fd == -1) break;
            if (FD_ISSET(states[i].fd, &sets2)) {
                printf("Receiving\n");
                len = recv(states[i].fd, buf, sizeof(udpctl_header), 0);
                if (len < 0) {
                    perror("Failed to recv");
                    // TODO: Error
                } else if (len == 0) {
                    printf("Connection closed (%d).\n", states[i].fd);
                    FD_CLR(states[i].fd, &sets);
                    close(states[i].fd);
                    states[i].fd = -1;
                } else { // 正常に受信できたら
                    for (; len <
                           sizeof(udpctl_header);) { // ヘッダの長さ分だけ受信する,
                                                     // TODO: 無限ループの可能性
                        add_len = recv(states[i].fd, &buf[len],
                                       sizeof(udpctl_header) - len, 0);
                        len += add_len;
                    }
                    hdr_ptr = reinterpret_cast<udpctl_header *>(buf);
                    for (; len <
                           sizeof(udpctl_header) +
                               hdr_ptr->length;) { // メッセージ部も受信する,
                                                   // TODO: 無限ループの可能性
                        add_len = recv(
                            states[i].fd, &buf[len],
                            sizeof(udpctl_header) + hdr_ptr->length - len, 0);
                        len += add_len;
                    }
                    if (handle_udpctl_packet(&states[i], hdr_ptr, len) != 0) {
                        printf("Connection reset (%d)\n", states[i].fd);
                    }
                }
            }
        }
    }
}

int main() {

    uint32_t next_id = 0, udp_intents_map_fd = 0;
    int res;
    bpf_map_info map_info{};
    uint32_t map_info_len = sizeof(map_info);

    // bpf_mapを1つずつ調べて目的のものに当たるまで探す
    while (true) {
        res = bpf_map_get_next_id(next_id, &next_id);
        if (res < 0) {
            if (errno == ENOENT) {
                break;
            }
            perror("Failed to execute bpf_map_get_next_id");
            exit(EXIT_FAILURE);
        }

        map_fd = bpf_map_get_fd_by_id(next_id);
        if (map_fd < 0) {
            perror("Failed to execute bpf_map_get_fd_by_id");
            exit(EXIT_FAILURE);
        }

        res = bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len);
        if (res < 0) {
            perror("Failed to execute bpf_obj_get_info_by_fd");
            exit(EXIT_FAILURE);
        }

        printf("bpf_map found (id: %d, fd: %d, name: %s)\n", next_id, map_fd,
               map_info.name);

        if (strcmp(map_info.name, "udp_intents") ==
            0) { // bpf_mapの名前がmatchしたら
            udp_intents_map_fd = map_fd;
        }
    }

    // 目的のbpf_mapが見つからなかったら終了
    if (udp_intents_map_fd == 0) {
        fprintf(stderr, "UDP intents map not found\n");
        exit(EXIT_FAILURE);
    } else {
        printf("udp_intents map found! (fd: %d)\n", udp_intents_map_fd);
    }

    // Ctrl+Cのハンドラ
    struct sigaction sig_int_handler;
    sig_int_handler.sa_handler = terminate;
    sigemptyset(&sig_int_handler.sa_mask);
    sig_int_handler.sa_flags = 0;
    sigaction(SIGINT, &sig_int_handler, NULL);

    termios attr{};
    tcgetattr(0, &attr);
    attr.c_lflag &= ~ICANON;
    attr.c_cc[VTIME] = 0;
    attr.c_cc[VMIN] = 1;
    tcsetattr(0, TCSANOW, &attr);
    fcntl(0, F_SETFL, O_NONBLOCK);

    // インテントのデフォルト値を設定
    /*
    for (int i = 0x0000; i < 0xffff; i++) {
        struct key intert_key = {
            .local_address = htonl(0),
            .local_port = htons(i)
        };

        int res = bpf_map_update_elem(udp_intents_map_fd, &intert_key, &i, BPF_ANY);
        if (res < 0) {
            printf("Failed to update %d '%s'\n", i, strerror(errno));
            printf("%d\n", res);
            terminate(-1);
        }
    }
    */

    run_agent();

    /*


    for (int i=0; i<0xff; i++){
        int* value = (int*) malloc(sizeof(int));
        *value = i;
        int res = bpf_map_update_elem(map_fd, &i, value, BPF_ANY);
        if(res < 0){
            printf("Failed to create '%s'\n", strerror(errno));
            printf("%d\n", res);
        }
    }
    */

    while (true) {
        sleep(1);
    }

    return 0;
}
