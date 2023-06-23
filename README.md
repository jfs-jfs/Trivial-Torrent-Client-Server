# Trivial-Torrent-Client-Server

This project was made during the curse on networks at my university. It strives to teach the students how protocols are implemented at low levels as well as how applications communicate over the network.  It is based in the trivial torrent protocol which in turn is a highly simplified version of the bittorrent protocol [https://en.wikipedia.org/wiki/BitTorrent].

# Specification

## The protocol

The trivial torrent protocol is a p2p communications protocol designed to share files among multiple peers. In the trivial torrent protocol, a peer can be either a client or a server but not both at once. Servers listen to a specific TCP port where they make a single file available for download.

### Unit of transfer: Block

For the purposes of the protocol files are split into consecutive blocks of raw data, which are transmitted from servers to clients. All blocks are 64KiB in size, except possibly the last one, that can be smaller. All blocks are indexed starting from 0, in order of occurrence in the file.

A block always contains at least 1 byte. Hence, empty files have 0 blocks.

Not all the blocks of a file need to reside in the same sever. A file can be split into multiple servers and the clients are expected to connect to multiple servers and requests the needed blocks.

### Meta-info file

Has the extension `.ttorrent` and the name of the file it references. It describes the necessary information to share a file for both clients and servers.

The meta-info file must contain:

- The target file length.
- The SHA256 hash of each block.
- A list of addresses of multiple peer servers which the file can be found on.

### Cycle of life

#### Client

```
1. Load metainfo file.
	1.1 Check existance of associated file.
	1.2 Check SHA256 hashes coincide with the file, taking into account which blocks are correct and which ones are not.
2. For each server in the metainfo file:
	2.1 Connect to said server.
	2.2 For each incorrect block(1.2):
		2.2.1 Send a request to the server.
		2.2.2 If the server responds with the block, store it to the target file.
		2.2.3 If the server signals the unavailability of the block, do nothing.
	2.3 Close connection
3. Terminate
```

#### Server

```
1. Load metainfo file.
	1.1 Check existance of associated file.
	1.2 Check SHA256 hashes coincide with the file, taking into account which blocks are correct and which ones are not.
2. Listen to incoming connections.
3. For each connection:
	3.1 Wait for a message.
	3.2 If a message requests a block that can be served, respond with the appropiate message followed by the block data.
	3.3 If the block can not be served, respond with a message singaling the unavailability of the block.
```

### Write format

There is only one type of message, and it consists of four fields:

```c
uint32_t magic_number;
uint8_t message_code;
uint64_t block_number;
uint8_t payload[payload_size];
```

All fields shall be transmitted in network byte order.

There are three different message codes:

- `MSG_REQUEST`: only used by clients to request blocks from the server. The payload field shall be left empty.
- `MSG_RESPONSE_OK`: used to signal from the server to the client, that the requested block can be served. The payload shall contain the data block with index in `block_number` field.
- `MSG_RESPONSE_NA`: used to signal from the server to the client, that the requested block can not be served. The payload field shall be left empty.

# Design

With the file input output functionality given, we only need to work on the two different loops the program can have, the client loop and the server loop. Also we got a choice on the server loop, we can make a forking server or a polling server. I chose to make both and pick the functionality at compile time with a define sentence.

Looking at the life cycles for client and server we can see that both share the the set up (point 1 and it's children) and both need to send and receive messages across the network. With that in mind I decided to make the main function to fulfil the set-up requirements  and jump to one or the other loop given the command line arguments supplied to the program. Then both, client and server, are going to use the same functions to send and receive trying to minimize error surface.

Given that 2 out of the 3 messages are going to be 13 bytes (when the payload is set to nothing) I decided to drop the payload field from the packet. That way I will just append it with another send to the end when need it and forget about it when not.

All and all I ended up with 11 functions plus the main function:

```c
/* FUNCTION DECLARATION */
// -- Main loops
int main_loop_client(struct torrent_t* torrent);	// Client loop
int main_loop_forking_server(struct torrent_t* torrent, int port);	// Server loop - forking implementation
int main_loop_polling_server(struct torrent_t* torrent, int port);	// Server loop - polling implementation

// -- Send functions
int send_block(int fd, uint64_t blk_n, struct block_t* blk);	// Send a full block
int send_raw_msg(uint64_t blk_n, uint8_t message_code, int fd); // Send the first 13 bytes of the message

// -- Receive functions
int recv_raw_msg(int fd, struct raw_msg* packet);	// Receive the header of a packet(13 bytes)
int recv_and_store_block(int fd, uint64_t blk_n, struct torrernt_t* torrent); // Receive a block and store it in the target file

// -- Helper functions
void pquit(char* err_msg);	// Print a message and exit execution
void mquit(char* err_msg);	// Print perror and exit execution
char* get_last_dot(char* str);	// Returns pointer to the last dot in a string or NULL
bool torrent_completed(struct torrent_t* torrent);	// Checks wether or not we got the whole file
```

And created one new `struct`:

```c
struct raw_msg {
    uint32_t magic_number;
    uint8_t message_code;
    uint64_t block_n;
};
```

# Things I would change

Given I made the two options for the server, polling and forking, I should had considered to extract the main functionality into functions that way I wouldn't have to repeat the same code two times. A side from this, I am pretty proud of this project and had fun making it.

# Everything put together

You can find the code in `code.c`

