#pragma once
/* IO facade for abstracting wire data formats and channel types */
#include <cstd/std.h>
#include <cstd/unix.h>
#include <relay/relay_packet.h>
#include <relay/relay_client.h>
#include <file/source.h>
#include <file/sink.h>

/* IO formats */
enum io_format {
	io_null = 0,
	io_raw = 1,
	io_packet = 2,
	io_relay = 3
};

/* If USE_RAW is defined or fd is a regular file, use fallback, else use relay */
enum io_format try_relay(int fd, enum io_format fallback);

/* Format to string to format to string */
const char *io_format_str(enum io_format fmt);
enum io_format io_format_val(const char *str);

/* Block size when reading in RAW mode */
extern size_t io_intf_raw_block_size;

struct io_intf {
	/* Type set in read packets for data read in raw/packet mode */
	const char *type_in;
	/* Only type for which data will be emitted in raw/packet mode */
	const char *type_out;
	/* Local name */
	const char *local;
	/* Format */
	enum io_format fmti;
	enum io_format fmto;
	/* File descriptors */
	struct file_source *fi;
	struct file_sink *fo;

	struct relay_client ri;
	struct relay_client ro;

	/* Max block size, for file IO */
	size_t raw_block_size;

	/* stat */
	bool has_si;
	bool has_so;
	struct stat si;
	struct stat so;
};

enum io_handler_result {
	/* Try next handler / pass to next stage */
	iohr_ignore = 0,
	/* Handled, pass to next stage */
	iohr_handled = 1,
	/* Packet consumed, do not pass to next stage */
	iohr_consumed = 2,
	/* Terminate loop */
	iohr_terminate = 3
};

typedef enum io_handler_result io_handler_func(struct io_intf *io, const struct relay_packet *p, void *arg);

struct io_handler {
	const char *type;
	io_handler_func *func;
	void *arg;
};

/*
 * local is the local name, used for authenticating against a relay server if
 * output backend is a socket.  Also, incoming packets that are not addressed to
 * this name (if it is not NULL) are silently forwarded on by
 * io_intf_recv_relay.
 *
 * fi/fo may be NULL or file_{sink,source} backends for the interface to use.
 * Despite the name, these just wrap file descriptors, and may refer to e.g.
 * pipes, sockets instead of files.
 *
 * fmti, fmto are input and output data format specifiers.  The try_relay(fmt)
 * function may be used to use relay format when possible and a fallback format
 * for files.
 *
 * type_in is set in type field of packets received in non-relay format.
 *
 * type_out is set in outgoing packets with NULL type field.
 */
bool io_intf_init(struct io_intf *inst, const char *local, struct file_source *fi, struct file_sink *fo, enum io_format fmti, enum io_format fmto, const char *type_in, const char *type_out);

/*
 * Returned packet will always have null terminator appended without affecting
 * apparent packet length, i.e. null set at packet->data[packet->length]
 *
 * Returns false on error, true with *out == NULL on EOF
 */
bool io_intf_recv(struct io_intf *inst, struct relay_packet **out);

/* Handle the next message (using the given list of handlers) */
bool io_intf_handle(struct io_intf *inst, const struct io_handler handlers[], size_t handler_count);

/*
 * Run a message loop, dispatching messages to the appropriate handler(s) via
 * chain-of-command pattern.
 */
void io_intf_loop(struct io_intf *inst, const struct io_handler handlers[], size_t handler_count);

bool io_intf_send(struct io_intf *inst, const char *type, const char *remote, const void *buf, const size_t length);

/* Forward a received packet on to the output */
bool io_intf_forward(struct io_intf *inst, const struct relay_packet *data);

void io_intf_destroy(struct io_intf *inst);
