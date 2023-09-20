/**
 * Userspace program for PFN UDP research
 */
#include <algorithm>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <termios.h>

#include "../agent/ctrl_sock.h"
#include "../bpf/ctrl_sock_bpf.h"

int map_set_intent_fd;
int map_set_opt_exp_fd;
int map_rcvd_opt_exp_fd;
ring_buffer *rb_rcvd_opt_exp;
int rb_rcvd_opt_exp_fd;
int map_rcvd_opt_time_fd;
ring_buffer *rb_rcvd_opt_time;
int rb_rcvd_opt_time_fd;

enum connection_state { closed, sock_open, ctrl_open };

const char *connection_state_strings[] = {
    "closed",
    "sock_open",
    "ctrl_open",
};

struct ctrl_socket_state {
    int fd;
    connection_state type;
    user_sock_t user_sock;
    uint16_t received_size;
    uint8_t received_buffer[MAX_MESSAGE_SIZE + 1];
};

ctrl_socket_state states[MAX_CONNECTION];

void terminate(int code) {
    printf("terminated (%d)\n", code);
    unlink(CTRL_SOCKET_PATH);
    exit(code);
}

int handle_ctrl_message(ctrl_socket_state *state, msg_header *hdr, ssize_t len) {
    printf("handle packet type %d from %d\n", hdr->type, state->fd);
    switch (hdr->type) {
    case TYPE_OPEN: {
        msg_open *open_ptr = (msg_open *)hdr;
        printf("openmsg!\n");
        state->type = connection_state::ctrl_open;

        state->user_sock.pid = open_ptr->user_sock.pid;
        state->user_sock.sock_fd = open_ptr->user_sock.sock_fd;

    } break;
    case TYPE_CTRL_TEST_CONNECTION: {
        printf("test connection (fd: %d)\n", state->fd);
        msg_ctrl_test_con *ctrl_test_con_ptr = (msg_ctrl_test_con *)hdr;

        msg_ctrl_test_con_reply *ctrl_test_con_reply_buf = (msg_ctrl_test_con_reply *)malloc(sizeof(msg_ctrl_test_con_reply));
        ctrl_test_con_reply_buf->hdr.length = sizeof(msg_ctrl_test_con_reply);
        ctrl_test_con_reply_buf->hdr.type = TYPE_NOTIFY_TEST_CONNECTION_REPLY;
        ctrl_test_con_reply_buf->test_num = ctrl_test_con_ptr->test_num;
        send(state->fd, ctrl_test_con_reply_buf, sizeof(msg_ctrl_test_con_reply), 0);

        free(ctrl_test_con_reply_buf);
    } break;
    case TYPE_CTRL_SET_OPTION_EXPERIMENTAL: {
        printf("set opt exp (fd: %d)\n", state->fd);
        msg_ctrl_set_opt_exp *msg_ctrl_set_opt_exp_ptr = (msg_ctrl_set_opt_exp *)hdr;

        int key = 4;

        map_set_opt_exp_value value;
        value.value = msg_ctrl_set_opt_exp_ptr->value;
        value.set_type = msg_ctrl_set_opt_exp_ptr->set_type;
        value.flow = msg_ctrl_set_opt_exp_ptr->flow;

        int res = bpf_map_update_elem(map_set_opt_exp_fd, &key, &value, BPF_ANY);
        if (res < 0) {
            printf("Failed to update intent '%s'\n", strerror(errno));
            printf("%d\n", res);
            terminate(EXIT_FAILURE);
        }

        printf("updated exp value (fd: %d)\n", state->fd);
    } break;
    case TYPE_CTRL_SUBSCRIBE_OPTION_EXPERIMENTAL: {
        printf("subscribe opt exp (fd: %d)\n", state->fd);

    } break;
    case TYPE_CTRL_SET_OPTION_TIMESTAMP: {
        printf("set opt time (fd: %d)\n", state->fd);

    } break;
    default:
        printf("unimplemented!\n");
        break;
    }

    return 0;
}

[[noreturn]] void run_agent() {
    int fd_accept, max_fd;

    fd_accept = socket(AF_UNIX, SOCK_STREAM, 0); // Open socket for accept
    if (fd_accept < 0) {
        perror("failed to open socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un sun = {};
    socklen_t sun_len;
    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;
    strcpy(sun.sun_path, CTRL_SOCKET_PATH);
    sun_len = sizeof(sun);

    int res;

    res = bind(fd_accept, (struct sockaddr *)&sun, sun_len); // Bind sock file
    if (res < 0) {
        perror("failed to bind address");
        shutdown(fd_accept, SHUT_RDWR);
        close(fd_accept);
        unlink(CTRL_SOCKET_PATH);
        exit(EXIT_FAILURE);
    }

    res = listen(fd_accept, MAX_CONNECTION); // Start to listen
    if (res < 0) {
        perror("failed to listen");
        shutdown(fd_accept, SHUT_RDWR);
        close(fd_accept);
        unlink(CTRL_SOCKET_PATH);
        exit(EXIT_FAILURE);
    }

    chmod(CTRL_SOCKET_PATH, 0777);

    fd_set sets, sets2; // For update, for use
    FD_ZERO(&sets);
    FD_ZERO(&sets2);
    FD_SET(fd_accept, &sets);
    FD_SET(STDIN_FILENO, &sets);
    FD_SET(rb_rcvd_opt_exp_fd, &sets);
    FD_SET(rb_rcvd_opt_time_fd, &sets);

    max_fd = std::max(fd_accept, std::max(rb_rcvd_opt_exp_fd, rb_rcvd_opt_time_fd));

    for (int i = 0; i < MAX_CONNECTION; i++) { // Initialize state table
        states[i].fd = -1;
        states[i].type = connection_state::closed;
        states[i].received_size = 0;
    }

    int new_fd;
    ssize_t len, add_len;
    msg_header *hdr_ptr;

    while (true) {
        memcpy(&sets2, &sets, sizeof(sets));
        res = select(max_fd + 1, &sets2, nullptr, nullptr, nullptr);
        if (res < 0) {
            perror("failed to select");
        }
        if (FD_ISSET(STDIN_FILENO, &sets2)) {
            int input = getchar();
            if (input == 's') {
                printf("\nshow states\n");
                for (int i = 0; i < MAX_CONNECTION; i++) {
                    printf("%d: state=%s", i, connection_state_strings[(int)states[i].type]);

                    if (states[i].type >= connection_state::sock_open) {
                        printf(", fd=%d", states[i].fd);
                    }
                    if (states[i].type >= connection_state::ctrl_open) {
                        printf(", user_sock=pid:%d/fd:%d rcvd=%d", states[i].user_sock.pid, states[i].user_sock.sock_fd, states[i].received_size);
                    }
                    printf("\n");
                }
            }
        }
        if (FD_ISSET(fd_accept, &sets2)) { // If sock for accept receive something
            new_fd = accept(fd_accept, (struct sockaddr *)&sun, &sun_len);
            if (new_fd < 0) {
                perror("failed to accept");
                unlink(CTRL_SOCKET_PATH);
                exit(EXIT_FAILURE);
            }
            printf("new accept (%d).\n", new_fd);

            for (int i = 0; i < MAX_CONNECTION; i++) {
                if (states[i].fd == -1) {
                    states[i].fd = new_fd;
                    states[i].type = connection_state::sock_open;
                    break;
                }
                if (i == MAX_CONNECTION - 1) {
                    fprintf(stderr, "already connected max connections\n");
                    exit(EXIT_FAILURE); // TODO: Exitしないように
                }
            }

            FD_SET(new_fd, &sets);
            if (new_fd > max_fd) {
                max_fd = new_fd;
            }
        }

        if (FD_ISSET(rb_rcvd_opt_exp_fd, &sets2)) {
            ring_buffer__poll(rb_rcvd_opt_exp, 0);
        }

        if (FD_ISSET(rb_rcvd_opt_time_fd, &sets2)) {
            ring_buffer__poll(rb_rcvd_opt_time, 0);
        }

        for (int i = 0; i < MAX_CONNECTION; i++) {
            if (states[i].fd == -1)
                break;
            if (FD_ISSET(states[i].fd, &sets2)) {
                int recv_size;
                if (states[i].received_size < sizeof(msg_header)) {           // まだヘッダも受信できてない場合
                    recv_size = sizeof(msg_header) - states[i].received_size; // ひとまずヘッダを受信する
                } else {                                                      // ヘッダは受信できているとき
                    hdr_ptr = (msg_header *)&states[i].received_buffer;
                    recv_size = hdr_ptr->length - states[i].received_size; // メッセージ本体を受信する
                }

                len = recv(states[i].fd, &states[i].received_buffer[states[i].received_size], recv_size, 0);
                //printf("len: %d\n", len);
                if (len < 0) { // Failure
                    perror("failed to recv");
                    // TODO: Error
                } else if (len == 0) { // Close connection
                    printf("connection closed (%d).\n", states[i].fd);
                    FD_CLR(states[i].fd, &sets);
                    close(states[i].fd);
                    states[i].type = connection_state::closed;
                    states[i].fd = -1;
                    states[i].received_size = 0;
                } else { // 正常に受信できたら
                    states[i].received_size += len;
                    //printf("size: %d\n", states[i].received_size);
                    if (states[i].received_size >= sizeof(msg_header)) { // ヘッダを受信できている場合
                        hdr_ptr = (msg_header *)&states[i].received_buffer;

                        if(hdr_ptr->length <= sizeof(msg_header)){
                            fprintf(stderr, "invalid header message size %d\n", hdr_ptr->length);
                        }

                        if (hdr_ptr->length == states[i].received_size) {             // ヘッダに書かれているメッセージサイズと受信済みのサイズが等しいとき
                            if (handle_ctrl_message(&states[i], hdr_ptr, len) != 0) { // メッセージの処理に送る
                                printf("connection reset (%d)\n", states[i].fd);
                                FD_CLR(states[i].fd, &sets);
                                close(states[i].fd);
                                states[i].type = connection_state::closed;
                                states[i].fd = -1;
                                states[i].received_size = 0;
                            } else {
                                states[i].received_size = 0;
                            }
                        } else if (hdr_ptr->length > states[i].received_size) { // まだ足りないとき
                            // 次のループでチャレンジ
                        } else { // 大きすぎるとき(Agentのバグ以外では発生しない)
                            fprintf(stderr, "received message is too large\n");
                            terminate(EXIT_FAILURE);
                        }
                    }
                }
            }
        }
    }
}


int handle_rcvd_opt_exp(void *ctx, void *data, size_t data_sz) {
    printf("handle_rcvd_opt_exp!!\n");

    if (data_sz < sizeof(map_rcvd_opt_exp_value)) {
        fprintf(stderr, "error in handle_rcvd_opt_exp\n");
        terminate(EXIT_FAILURE);
    }

    map_rcvd_opt_exp_value *rcvd_val = (map_rcvd_opt_exp_value *)data;

    printf("received exp opt %d from %s:%d\n", rcvd_val->value, inet_ntoa(in_addr{.s_addr = rcvd_val->addr.address}), rcvd_val->addr.port);

    msg_notify_per_pkt_opt_exp *msg = (msg_notify_per_pkt_opt_exp *)malloc(sizeof(msg_notify_per_pkt_opt_exp));
    msg->hdr.length = sizeof(msg_notify_per_pkt_opt_exp);
    msg->hdr.type = TYPE_NOTIFY_PER_PACKET_OPTION_EXP;
    msg->exp_val = rcvd_val->value;

    send(states[0].fd, msg, sizeof(msg_notify_per_pkt_opt_exp), 0);

    free(msg);

    return 0;
}

int handle_rcvd_opt_time(void *ctx, void *data, size_t data_sz) {
    printf("handle_rcvd_opt_time!!\n");

    if (data_sz < sizeof(uint32_t)) {
        fprintf(stderr, "error in handle_rcvd_opt_exp\n");
        terminate(EXIT_FAILURE);
    }

    uint32_t val = *((uint32_t *) data);

    printf("received time opt %d\n", val);

    return 0;
}

int main() {

    uint32_t next_id = 0, map_fd = 0;
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
            perror("failed to execute bpf_map_get_next_id");
            exit(EXIT_FAILURE);
        }

        map_fd = bpf_map_get_fd_by_id(next_id);
        if (map_fd < 0) {
            perror("failed to execute bpf_map_get_fd_by_id");
            exit(EXIT_FAILURE);
        }

        res = bpf_obj_get_info_by_fd(map_fd, &map_info, &map_info_len);
        if (res < 0) {
            perror("failed to execute bpf_obj_get_info_by_fd");
            exit(EXIT_FAILURE);
        }

        printf("bpf_map found (id: %d, fd: %d, name: %s)\n", next_id, map_fd, map_info.name);

        if (strcmp(map_info.name, "set_intent") == 0) { // bpf_mapの名前がmatchしたら
            map_set_intent_fd = map_fd;
        } else if (strcmp(map_info.name, "set_opt_exp") == 0) {
            map_set_opt_exp_fd = map_fd;
        } else if (strcmp(map_info.name, "rcvd_opt_exp") == 0) {
            map_rcvd_opt_exp_fd = map_fd;
        } else if (strcmp(map_info.name, "rcvd_opt_time") == 0) {
            map_rcvd_opt_time_fd = map_fd;
        }
    }

    bool found_all_maps = true;

    if (map_set_intent_fd == 0) {
        fprintf(stderr, "map set_intent not found\n");
        found_all_maps = false;
    } else {
        printf("map set_intent found! (fd: %d)\n", map_set_intent_fd);
    }

    if (map_set_opt_exp_fd == 0) {
        fprintf(stderr, "map set_opt_exp not found\n");
        found_all_maps = false;
    } else {
        printf("map set_opt_exp found! (fd: %d)\n", map_set_opt_exp_fd);
    }

    if (map_rcvd_opt_exp_fd == 0) {
        fprintf(stderr, "map rcvd_opt_exp not found\n");
        found_all_maps = false;
    } else {
        printf("map rcvd_opt_exp found! (fd: %d)\n", map_rcvd_opt_exp_fd);
    }

    if (map_rcvd_opt_time_fd == 0) {
        fprintf(stderr, "map rcvd_opt_time not found\n");
        found_all_maps = false;
    } else {
        printf("map rcvd_opt_time found! (fd: %d)\n", map_rcvd_opt_time_fd);
    }

    // 1つでも目的のBPF mapがら見つからなかったら終了
    if (!found_all_maps) {
        exit(EXIT_FAILURE);
    }

    // Ring buffer
    rb_rcvd_opt_exp = ring_buffer__new(map_rcvd_opt_exp_fd, handle_rcvd_opt_exp, NULL, NULL);
    rb_rcvd_opt_exp_fd = ring_buffer__epoll_fd(rb_rcvd_opt_exp);

    rb_rcvd_opt_time = ring_buffer__new(map_rcvd_opt_time_fd, handle_rcvd_opt_time, NULL, NULL);
    rb_rcvd_opt_time_fd = ring_buffer__epoll_fd(rb_rcvd_opt_time);

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

    run_agent(); // Start agent

    return 0;
}
