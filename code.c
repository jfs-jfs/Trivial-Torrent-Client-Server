// Trivial Torrent

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <endian.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>

// Teacher given files
#include "file_io.h"
#include "logger.h"

static const uint32_t MAGIC_NUMBER = 0xde1c3230; // = htonl(0x30321cde);

static const uint8_t MSG_REQUEST = 0x00;
static const uint8_t MSG_RESPONSE_OK = 0x01;
static const uint8_t MSG_RESPONSE_NA = 0x02;

typedef uint8_t bool;
typedef struct sockaddr_in sockaddr_in;

#define false 0
#define true 1
#define DEFAULT_PORT 8080
#define TORRENT_EXTENSION ".ttorrent"

// Uncomment to run a polling server
//########################################################################
//#define POLLING  // Uncomment to run a polling server
//########################################################################

struct raw_msg {
    uint32_t magic_number;
    uint8_t message_code;
    uint64_t block_n;
};

enum {RAW_MESSAGE_SIZE = 13};


/* FUNTION DECLARATIONS */
//  -- Main loops
int main_loop_client(struct torrent_t *torrent);
int main_loop_forking_server(struct torrent_t *torrent, int port);
int main_loop_polling_server(struct torrent_t *torrent, int port);
// Helper functions
void pquit(char *err_msg);
void mquit(char *err_msg);
char *get_last_dot(char *str);
bool torrent_completed(struct torrent_t *torrent);

int recv_raw_msg(int fd, struct raw_msg *packet);
int recv_and_store_block(int fd, uint64_t blk_n, struct torrent_t *torrent);

int send_block(int fd, uint64_t blk_n, struct block_t *blk);
int send_raw_msg(uint64_t blk_n, uint8_t message_code, int fd);

/**
 * Main function.
 */
int main(int argc, char **argv) {


    set_log_level(LOG_DEBUG);
    log_printf(LOG_INFO, "Trivial Torrent (build %s %s) by %s", __DATE__, __TIME__, "Jacob XXXXX XXXXX");

    bool run_as_srv;
    int port;
    char *torrent_filename;
    struct torrent_t torrent_obj;

    // Parse command line
    // Accept only 2 and 4 arguments
    if (argc == 2 || argc == 4) {
        if (argc == 2) {
            /* client */
            run_as_srv = false;
            log_printf(LOG_INFO, "Client mode");
        }
        else {
            /* server */
            run_as_srv = true;
            port = atoi(argv[2]);
            if(port <= 0)
                mquit("Invalid server port ");
            log_printf(LOG_INFO, "Server mode (port %s)", argv[2]);
        }

        /* common */
        torrent_filename = argv[argc - 1];

        // Check extension
        // 1. Find where the dot starts
        char *extension_start = get_last_dot(torrent_filename);
        // 2. Check all the extension
        if (extension_start == NULL || strcmp(extension_start, TORRENT_EXTENSION) != 0)
            mquit("Invalid torrent file extension");

        // Create torrent from metainfo file
        // 1. 3rd param of create_torrent_from_metainfo_file, we will assume is the same as
        // the torrent mateinfo file but without the extension
        char *downloaded_torrent_filename = strdup(torrent_filename);
        if (downloaded_torrent_filename == NULL)
            pquit("strdup");
        downloaded_torrent_filename[extension_start - torrent_filename] = '\0';

        // 2. Fill the torrent_t struct
        // Check if everything goes right --> pquit as function toucher the erron
        if (create_torrent_from_metainfo_file(torrent_filename, &torrent_obj, downloaded_torrent_filename) != 0)
            pquit("create_torrent_from_metainfo_file");

        // 3. Free it as we won't be using it any more
        free(downloaded_torrent_filename);

        if (run_as_srv) {
            // CALL SERVER MAIN LOOP
            #ifdef POLLING
            log_printf(LOG_INFO, "Server in polling mode");
            if (main_loop_polling_server(&torrent_obj, port) < 0)
                pquit("main_loop_server");
            #else
            log_printf(LOG_INFO, "Server in forking mode");
            if (main_loop_forking_server(&torrent_obj, port) < 0)
                pquit("main_loop_server");
            #endif

            if (destroy_torrent(&torrent_obj) != 0)
                pquit("destroy_torrent");

            /* SERVER ENDS IN SUCCESS! */
        	return EXIT_SUCCESS;
        } else {
            // CALL CLIENT MAIN LOOP
            if (main_loop_client(&torrent_obj) < 0)
                pquit("main_loop_client");

            if (destroy_torrent(&torrent_obj) != 0)
                pquit("destroy_torrent");

            /* CLIENT ENDS WITH SUCCESS !*/
            return EXIT_SUCCESS;
        }
    } else
        mquit("Usage is: ttorrent [-l port] file.ttorrent\n");

    return 0;
}

/*
 _          _                    __
| |__   ___| |_ __   ___ _ __   / _|_   _ _ __   ___
| '_ \ / _ \ | '_ \ / _ \ '__| | |_| | | | '_ \ / __|
| | | |  __/ | |_) |  __/ |    |  _| |_| | | | | (__
|_| |_|\___|_| .__/ \___|_|    |_|  \__,_|_| |_|\___|
             |_|
*/

//Function to print a message and exit
void mquit(char *err_msg) {

    assert(err_msg != NULL);

    fprintf(stderr, "ERROR: %s\n", err_msg);
    exit(EXIT_FAILURE);
}

//Function that prints the error and exit
void pquit(char *err_msg) {

    assert(err_msg != NULL);

    perror(err_msg);
    exit(EXIT_FAILURE);
}

//Get pointer to the last dot in a string or NULL
char *get_last_dot(char *str) {

    assert(str != NULL);

    char *last_dot = NULL;
    for (int i = 0; str[i] != '\0'; i++)
        if (*(str + i) == '.')
            last_dot = (str + i);
    return last_dot;
}

//Check if torrent is completed
bool torrent_completed(struct torrent_t *torrent) {

    assert(torrent != NULL);

    for (size_t i = 0; i < torrent->block_count; i++)
        if (torrent->block_map[i] == 0)
            return false;
    return true;
}

//Function used to receive a message and store it, this function is used to receive the header. Returns minus 1 on error.
int recv_raw_msg(int fd, struct raw_msg *packet) {

    assert(packet != NULL);
    assert(fd > 0);

    ssize_t rc;
    uint8_t buffer[RAW_MESSAGE_SIZE];
    if ((rc = recv(fd, &buffer, RAW_MESSAGE_SIZE, 0)) < 0) {
        return -1;
    }

    memcpy(&(packet->magic_number), buffer, sizeof(uint32_t));
    memcpy(&(packet->message_code), buffer + 4, sizeof(uint8_t));
    memcpy(&(packet->block_n), buffer + 5, sizeof(uint64_t));

    // assert(sizeof(int) >= sizeof(ssize_t));
    return (int)rc;
}


//Function used to receive a message and store it, this function is used to receive the payload. Returns minus 1 on error.
int recv_and_store_block(int fd, uint64_t blk_n, struct torrent_t *torrent) {

    assert(torrent != NULL);
    assert(fd > 0);
    assert(blk_n < torrent->block_count);

    uint64_t blk_sz = get_block_size(torrent, blk_n);
    struct block_t block;
    block.size = blk_sz;
    log_printf(LOG_INFO, "\tReading %d bytes of payload", blk_sz);
    ssize_t rc;
    if ((rc = recv(fd, &block, blk_sz, 0x100)) < 0) {
        return -1;
    }

    log_printf(LOG_INFO, "\tStoring block");
    if (store_block(torrent, blk_n, &block) < 0) {
        return -1;
    }

    // assert(sizeof(int) >= sizeof(ssize_t));
    return (int)rc;
}

//Function used to send a message, this function is used to send the header. Returns minus 1 on error and 0 if successfull
int send_block(int fd, uint64_t blk_n, struct block_t *blk) {

    assert(fd > 0);
    // blk_n always will be equal or bigger than 0 as it is unsigned
    // assert(blk_n >= 0);
    assert(blk != NULL);

    uint8_t buffer[RAW_MESSAGE_SIZE + blk->size];
    memcpy(buffer, &MAGIC_NUMBER, sizeof(uint32_t));
    memcpy((buffer + 4), &MSG_RESPONSE_OK, sizeof(uint8_t));
    memcpy((buffer + 5), &blk_n, sizeof(uint64_t));
    memcpy(buffer + 13, blk->data, blk->size);

    log_printf(LOG_INFO, "\t\t\tResponse will be { magic_number = 0x%X, block_number = %d, message_code = %d }",
               MAGIC_NUMBER, blk_n, MSG_RESPONSE_OK);

    if (send(fd, buffer, RAW_MESSAGE_SIZE + blk->size, 0) < 0)
        return -1;
    return 0;
}

// Funcrion to send the raw_message of 13 bytes. Returns minus 1 on error and 0 if successfully
int send_raw_msg(uint64_t blk_n, uint8_t message_code, int fd) {

    // MSG_RESPONSE_OK is send by send_block
    assert(message_code == MSG_REQUEST || message_code == MSG_RESPONSE_NA);
    // blk_n will always be equal or bigger than 0 as it is unisgned
    //assert(blk_n >= 0);
    assert(fd > 0);

    uint8_t buffer[RAW_MESSAGE_SIZE];
    memcpy(buffer, &MAGIC_NUMBER, sizeof(uint32_t));
    memcpy((buffer + 4), &message_code, sizeof(uint8_t));
    memcpy((buffer + 5), &blk_n, sizeof(uint64_t));

    if (message_code == MSG_REQUEST)
        log_printf(LOG_INFO, "\tRequesting block { magic_number=0x%X, block_number=%d, message_code=%d }",MAGIC_NUMBER, blk_n, message_code);

    if (send(fd, buffer, RAW_MESSAGE_SIZE, 0) < 0)
        return -1;
    return 0;
}

/*
                 _          __
 _ __ ___   __ _(_)_ __    / _|_   _ _ __   ___ ___
| '_ ` _ \ / _` | | '_ \  | |_| | | | '_ \ / __/ __|
| | | | | | (_| | | | | | |  _| |_| | | | | (__\__ \
|_| |_| |_|\__,_|_|_| |_| |_|  \__,_|_| |_|\___|___/
*/

int main_loop_client(struct torrent_t *torrent) {

    assert(torrent != NULL);

    bool completed = torrent_completed(torrent);
    for (uint64_t i = 0; !completed && i < torrent->peer_count; i++) {
        //  1.1 Connect to the server
        int sock_fd;
        sockaddr_in srv_addr;

        // Create it
        if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            return -1;

        // Initialize srv_addr
        memset(&srv_addr, 0, sizeof(sockaddr_in));
        srv_addr.sin_family = AF_INET;
        // Already in network byte order
        srv_addr.sin_port = torrent->peers[i].peer_port;

        // Create a uint32_t from an array of four uint8_t
        struct peer_information_t info = torrent->peers[i];
        uint32_t aux = (uint32_t)(info.peer_address[0] | (info.peer_address[1] << 8) |
                                  (info.peer_address[2] << 16) | (info.peer_address[3] << 24));
        // srv_addr.sin_addr.s_addr = *(uint32_t *)torrent->peers[i].peer_address; // -fsanitize=undefined -fno-sanitize-recover=all raises error
        srv_addr.sin_addr.s_addr = aux;
        log_printf(LOG_INFO, "Connecting to peer #%d...", i);

        // Try to connect: if not try next server
        if (connect(sock_fd, (struct sockaddr *)&srv_addr, sizeof(sockaddr_in)) < 0)
            continue;

        // 1.2 For each incorrect block in the downloaded file
        for (uint64_t j = 0; j < torrent->block_count; j++) {
            if (torrent->block_map[j] == 0) {

                // Ask for the block
                if (send_raw_msg(j, MSG_REQUEST, sock_fd) < 0) {
                    // Try the next server
                    break;
                }

                log_printf(LOG_INFO, "\tWaiting for response");

                struct raw_msg raw_response;

                if (recv_raw_msg(sock_fd, &raw_response) < 0) {
                    // Try next server
                    break;
                }

                log_printf(LOG_INFO, "\tResponse is { magic_number=0x%X, block_number=%d, message_code=%d }", raw_response.magic_number, raw_response.block_n, raw_response.message_code);

                if (raw_response.magic_number != MAGIC_NUMBER) {
                    log_printf(LOG_INFO, "\t\tMagic number does not match...Skipping server");
                    // Try next server
                    break;
                }
                else if (raw_response.message_code == MSG_RESPONSE_OK) {
                    // SAVE THE BLOCK
                    if (recv_and_store_block(sock_fd, raw_response.block_n, torrent) < 0) {
                        // Try next server
                        break;
                    }
                }
            }
            // Look for next one
        }
        completed = torrent_completed(torrent);

        // 1.3 Close Connection
        if (close(sock_fd)) {
            pquit("[CLIENT] close");
        }
    }

    if (completed) {
        log_message(LOG_INFO, "We got the whole file :-)");
    }

    log_message(LOG_INFO, "And we are done");
    return 0;
}

int main_loop_forking_server(struct torrent_t *torrent, int port) {

    assert(torrent != NULL);
    assert(port > 1);

    // Create the server
    int sock_fd;
    sockaddr_in srv_addr;

    log_printf(LOG_INFO, "Starting server....");
    // Create the socket
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    log_message(LOG_INFO, "\tsocket ok");

    // Binding the socket
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons((uint16_t)port);

    if ((bind(sock_fd, (const struct sockaddr *)&srv_addr, sizeof(srv_addr))) < 0)
        return -1;

    log_message(LOG_INFO, "\tbind ok");

    // Start Listening on it
    if ((listen(sock_fd, 100)) < 0)
        return -1;
    log_message(LOG_INFO, "\tlisten ok");

    // Preparations to enter the infinite loop
    int pid, new_fd;

    // Server Loop
    while (true) {
        log_printf(LOG_INFO, "\tListening to incoming connections");

        if ((new_fd = accept(sock_fd, NULL, NULL)) < 0) {
            log_printf(LOG_INFO, "\tError accepting client");
            return -1;
        }

        log_printf(LOG_INFO, "\tNew Incoming connection");
        if ((pid = fork()) == -1) {
            log_printf(LOG_INFO, "\tError on fork");
            return -1;
        } else if (pid == 0) {
            // CHILD PROCESS: Close parent fd and respond to the incoming query/message
            log_printf(LOG_INFO, "\t\tChild started to serve petition");

            if (close(sock_fd)) {
                log_printf(LOG_INFO, "[CHILD] Could not close parent fd");
            }

            int rc;
            bool end_connection = false;
            do {
                // Recieve query
                struct raw_msg query;
                if ((rc = recv_raw_msg(new_fd, &query)) < 0) {
                    log_printf(LOG_INFO, "\t\tRecv failed... Closing connection");
                    end_connection = true;
                    continue;
                }

                // Client closed connection?
                if (rc == 0) {
                    log_printf(LOG_INFO, "\t\tClient closed connection.");
                    end_connection = true;
                    continue;
                }

                log_printf(LOG_INFO, "\t\t\tRequest is { magic_number=0x%X, block_number=%d, message_code=%d }",query.magic_number, query.block_n, query.message_code);

                // MAGIC NUMBER OK?
                if (query.magic_number != MAGIC_NUMBER) {
                    log_printf(LOG_INFO, "\tWrong magic number...Closing connection.");
                    end_connection = true;
                    continue;
                }

                // Is he asking for a block?
                if (query.message_code != MSG_REQUEST) {
                    // As a server I can only respon to MSG_REQUEST
                    log_printf(LOG_INFO, "\tI cant do requested operation...Closing connection");
                    end_connection = true;
                    continue;
                }

                // Do I have the block?
                if (query.block_n <= torrent->block_count && torrent->block_map[query.block_n] == 1) {
                    // YES: send it to it
                    struct block_t block;
                    if (load_block(torrent, query.block_n, &block) < 0)
                        return -1;

                    if (send_block(new_fd, query.block_n, &block) < 0) {
                        log_printf(LOG_INFO, "\tUnaviable to send to client....Closing conection");
                        end_connection = true;
                        break;
                    }
                } else {
                    // NO: Send a MSG_RESPONSE_NA
                    log_printf(LOG_INFO, "\tBlock number %d isn't aviable...", query.block_n);

                    if (send_raw_msg(query.block_n, MSG_RESPONSE_NA, new_fd) < 0) {
                        log_printf(LOG_INFO, "\tUnaviable to send to client....Closing conection");
                        end_connection = true;
                        break;
                    }
                }

            } while (!end_connection);
            if (close(new_fd) < 0) {
                pquit("[CHILD] close");
            }
            exit(EXIT_SUCCESS);
        } else {
            // PARENT PROCESS: Close the fd to save resources
            if (close(new_fd))
                log_printf(LOG_INFO, "[PARENT] Could not close new fd");
        }
    }

    close(sock_fd);
    return 0;
}

int main_loop_polling_server(struct torrent_t *torrent, int port) {

    assert(torrent != NULL);
    assert(port > 1);

    // Create the server
    int sock_fd;
    int on = 1;
    sockaddr_in srv_addr;

    log_printf(LOG_INFO, "Starting server....");
    // Create the socket
    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    // Make the socket reusable
    // Doing it once it is enough as the others will inhert from here
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
        return -1;

    // Make the socket non-bloking
    // Doing it once it is enough as the others will inhert from here
    // We decided to use ioctl because we found more examples that we understood
    if (ioctl(sock_fd, FIONBIO, (char *)&on))
        return -1;

    log_message(LOG_INFO, "\tsocket ok");

    // Binding the socket
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    srv_addr.sin_port = htons((uint16_t)port);

    if ((bind(sock_fd, (const struct sockaddr *)&srv_addr, sizeof(srv_addr))) < 0)
        return -1;
    log_message(LOG_INFO, "\tbind ok");

    // Start Listening on it
    if ((listen(sock_fd, 100)) < 0)
        return -1;
    log_message(LOG_INFO, "\tlisten ok");


    // Preparations to enter the infinite loop

    // Number of active fd
    nfds_t nfds = 1;
    // helper
    nfds_t current_active = 1;

    // Struct to save the entries of fd and evetns
    struct pollfd polls_fd[200];

    // To control closed connections in the array
    bool compress_array = false;

    memset(&polls_fd, 0, sizeof(struct pollfd) * 200);

    // Setting up the server fd
    polls_fd[0].fd = sock_fd;
    polls_fd[0].events = POLLIN;

    // Server Loop
    while (true) {
        // Wait for polling activity
        log_message(LOG_INFO, "\tpolling...");
        if (poll(polls_fd, nfds, -1) < 0)
            return -1;

        log_message(LOG_INFO, "\t...poll has returned with events...");

        // Check all fd in poll_strc looking for events
        current_active = nfds;
        for (uint16_t i = 0; i < current_active; i++) {
            // Discriminate non events or events we dont handle
            // No event here jump to next fd
            if (polls_fd[i].revents == 0)
                continue;

            // Events we shouldn't find exit
            if (polls_fd[i].revents != POLLIN)
                return -1;

            // Event to process
            log_printf(
                LOG_INFO,
                "\t\tProcessing pollfd index %u (fd = %d, .events = %d, .revents = %d)",
                i,
                polls_fd[i].fd,
                polls_fd[i].events,
                polls_fd[i].revents);

            // I am reciving a new connection? or more than one??
            if (polls_fd[i].fd == sock_fd) {
                // YES
                log_message(LOG_INFO, "\t\tNew connection incoming");

                // Try to accept as many as I can and add each one to poll_strc
                int new_fd;
                do {
                    if ((new_fd = accept(sock_fd, NULL, NULL)) < 0) {
                        if (errno != EWOULDBLOCK)
                            return -1;
                        errno = 0;
                        break;
                    }
                    log_message(LOG_INFO, "\t\t\taccept ok");

                    // Add the new connection to the poll_strc structure
                    polls_fd[nfds].fd = new_fd;
                    polls_fd[nfds].events = POLLIN;
                    nfds++;

                } while (new_fd != -1);
            } else {
                // NO: must be someone sending something or disconneting
                bool close_connection = false;
                int rc;
                struct raw_msg query;

                /* service the client till closes connection */
                do {
                    /*
                                           ____ _   _ ___ ____ _   _    _
                                         / ___| | | |_ _/ ___| | | |  / \
                                        | |   | |_| || | |   | |_| | / _ \
                                        | |___|  _  || | |___|  _  |/ ___ \
                                        \____|_| |_|___\____|_| |_/_/   \_\
                                        */

                    // Get what they want to do
                    log_printf(LOG_INFO, "\t\t\tRecv'd message from client");
                    if ((rc = recv_raw_msg(polls_fd[i].fd, &query)) < 0) {
                        if (errno != EWOULDBLOCK) {
                            log_printf(LOG_INFO, "\t\tRecv filed... Closing connection");
                            close_connection = true;
                        }
                        break;
                    }

                    // Client closed connection
                    if (rc == 0) {
                        log_printf(LOG_INFO, "\tClient closed connection");
                        close_connection = true;
                        break;
                    }

                    log_printf(LOG_INFO, "\t\t\tRequest is { magic_number=0x%X, block_number=%d, message_code=%d }",query.magic_number, query.block_n, query.message_code);

                    // MAGIC NUMBER OK?
                    if (query.magic_number != MAGIC_NUMBER) {
                        // Close connection and exit
                        log_printf(LOG_INFO, "\tWrong magic number...Closing connection.");
                        close_connection = true;
                        break;
                    }

                    // Is he asking for a block?
                    if (query.message_code != MSG_REQUEST) {
                        // Server should only recieve MSG_REQUEST
                        log_printf(LOG_INFO, "\tI cant do requested operation...Closing connection");
                        close_connection = true;
                        break;
                    }

                    // Do I have the block?
                    if (query.block_n <= torrent->block_count && torrent->block_map[query.block_n] == 1) {
                        // YES send it to it
                        struct block_t block;
                        if (load_block(torrent, query.block_n, &block) < 0) {
                            return -1;
                        }

                        if (send_block(polls_fd[i].fd, query.block_n, &block) < 0) {
                            // I couldnt send to client close conection
                            log_printf(LOG_INFO, "\tUnaviable to send to client....Closing conection");
                            close_connection = true;
                            break;
                        }
                    } else {
                        // NO: Send a MSG_RESPONSE_NA
                        log_printf(LOG_INFO, "\tBlock number %d isn't aviable...", query.block_n);

                        if (send_raw_msg(query.block_n, MSG_RESPONSE_NA, polls_fd[i].fd) < 0) {
                            // I couldnt send to client close conection
                            log_printf(LOG_INFO, "\tUnaviable to send to client....Closing conection");
                            close_connection = true;
                            break;
                        }
                    }

                } while (true);

                // Close the connection
                if (close_connection) {
                    if (close(polls_fd[i].fd)) {
                        return -1;
                    }
                    polls_fd[i].fd = -1;
                    compress_array = true;
                    errno = 0;
                }
            }
        }

        if (compress_array) {
            compress_array = false;
            for (int i = 0; i < (int)nfds; i++) {
                if (polls_fd[i].fd == -1) {
                    for (int j = i; j < (int)nfds; j++) {
                        polls_fd[j].fd = polls_fd[j + 1].fd;
                    }
                    i--;
                    nfds--;
                }
            }
        }
    }

    return 0;
}
