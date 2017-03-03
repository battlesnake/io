#if 0
(
set -eu
gcc -Wall -Wextra -Werror -std=gnu11 -DSIMPLE_LOGGING -Ic_modules -o /dev/null $(find -name '*.c') -lpthread
)
exit 0
#endif
#include <cstd/std.h>
#include <cstd/unix.h>
#include <wildstr/wildstr.h>
#include "io.h"

/* #define DEBUG_io */

size_t io_intf_raw_block_size = 0x4000;

enum io_format try_relay(int fd, enum io_format fallback)
{
	const bool rawenv = getenv("IO_RAW") != NULL;
	struct stat s;
	const bool use_raw = rawenv || (fstat(fd, &s) == 0 && S_ISREG(s.st_mode));
	return use_raw ? fallback : io_relay;
}

const char *io_format_str(enum io_format fmt)
{
	switch (fmt) {
	case io_null: return "null";
	case io_raw: return "raw";
	case io_packet: return "packet";
	case io_relay: return "relay";
	default: return "invalid";
	}
}

enum io_format io_format_val(const char *str)
{
	if (strcmp(str, "null") == 0) {
		return io_null;
	} else if (strcmp(str, "raw") == 0) {
		return io_raw;
	} else if (strcmp(str, "packet") == 0) {
		return io_packet;
	} else if (strcmp(str, "relay") == 0) {
		return io_relay;
	} else {
		return (enum io_format) -1;
	}
}

static bool set_nonblock(int fd)
{
	int fl = fcntl(F_GETFL, fd);
	return fl >= 0 && fcntl(F_SETFL, fd, fl | O_NONBLOCK) != -1;
}

bool io_intf_init(struct io_intf *inst, const char *local, struct file_source *fi, struct file_sink *fo, enum io_format fmti, enum io_format fmto, const char *type_in, const char *type_out)
{
	memset(inst, 0, sizeof(*inst));
	inst->type_in = type_in;
	inst->type_out = type_out;
	inst->local = local;
	inst->fi = fi;
	inst->fo = fo;
	inst->fmti = fmti;
	inst->fmto = fmto;
	inst->raw_block_size = io_intf_raw_block_size;
	inst->has_si = fi && fstat(fi->fd, &inst->si) == 0;
	inst->has_so = fo && fstat(fo->fd, &inst->so) == 0;
	/*
	 * Need to authenticate if FD is a socket
	 * Don't authenticate input if it is this same socket as output.
	 *
	 * Actually, due to splitting sockets with pipes in the middle and all
	 * the fork/exec subprocess stuff, only auth output fd and only if it is
	 * a socket.
	 */
	bool auth = false;
	if (fmto == io_relay && !inst->has_so) {
		log_sysfail("fstat", "%d, ...", fo->fd);
		goto fail;
	} else {
		auth = S_ISSOCK(inst->so.st_mode);
	}
	if (fo) {
		if (!set_nonblock(fo->fd)) {
			log_error("Failed to configure fd%d to nonblocking mode", fo->fd);
			goto fail;
		}
		if (fmto == io_relay && !relay_client_init_fd(&inst->ro, local, fo->fd, fo->owns, auth)) {
			log_error("Failed to open fd%d in %s output mode for type %s", fo->fd, io_format_str(fmto), type_out);
			goto fail;
		}
	}
	if (fi) {
		if (!set_nonblock(fi->fd)) {
			log_error("Failed to configure fd%d to nonblocking mode", fi->fd);
			goto fail;
		}
		if (fmti == io_relay && !relay_client_init_fd(&inst->ri, local, fi->fd, fi->owns, false)) {
			log_error("Failed to open fd%d in %s input mode for type %s", fi->fd, io_format_str(fmti), type_in);
			goto fail;
		}
	}
	return true;
fail:
	io_intf_destroy(inst);
	return false;
}

static struct relay_packet *io_intf_recv_raw(struct io_intf *inst)
{
	struct relay_packet *res = malloc(sizeof(*res) + inst->raw_block_size + 1);
	memset(res, 0, sizeof(*res));
	res->data = (void *) (res + 1);
	ssize_t read = file_source_read_raw(inst->fi, inst->raw_block_size, res->data, false);
	if (read <= 0) {
		if (read == -1) {
			log_error("Failed to read from raw source");
		}
		free(res);
		return NULL;
	}
	res->length = read;
	res->data[res->length] = 0;
	if (inst->type_in != NULL) {
		strncpy(res->type, inst->type_in, RELAY_TYPE_LENGTH);
	}
	return res;
}

static struct relay_packet *io_intf_recv_packet(struct io_intf *inst)
{
	size_t length;
	void *buf = file_source_read_packet(inst->fi, &length);
	if (buf == NULL) {
		log_error("Failed to read from packet source");
		return NULL;
	}
	struct relay_packet *res = malloc(sizeof(*res) + length + 1);
	memset(res, 0, sizeof(*res));
	res->data = (void *) (res + 1);
	memcpy(res->data, buf, length);
	res->length = length;
	res->data[res->length] = 0;
	if (inst->type_in != NULL) {
		strncpy(res->type, inst->type_in, RELAY_TYPE_LENGTH);
	}
	free(buf);
	return res;
}

static struct relay_packet *io_intf_recv_relay(struct io_intf *inst)
{
	struct relay_packet *packet;
	while (true) {
		packet = relay_client_recv_packet(&inst->ri);
		if (packet == NULL) {
			log_error("Failed to read from relay source");
			return NULL;
		}
		if (inst->local == NULL || strcmp(inst->local, packet->local) == 0) {
			break;
		}
		if (!io_intf_forward(inst, packet)) {
			free(packet);
			return NULL;
		}
		free(packet);
	}
	return packet;
}

struct relay_packet *io_intf_recv(struct io_intf *inst)
{
	switch (inst->fmti) {
	case io_null: return NULL;
	case io_raw: return io_intf_recv_raw(inst);
	case io_packet: return io_intf_recv_packet(inst);
	case io_relay: return io_intf_recv_relay(inst);
	}
	return NULL;
}

static bool io_intf_send_raw(struct io_intf *inst, const char *type, const void *buf, const size_t length)
{
	if (inst->type_out != NULL && strcmp(inst->type_out, type) != 0) {
		return true;
	}
	bool res = file_sink_write_raw(inst->fo, buf, length);
	if (!res) {
		log_error("Failed to write to raw sink");
	}
	return res;
}

static bool io_intf_send_packet(struct io_intf *inst, const char *type, const void *buf, const size_t length)
{
	if (inst->type_out != NULL && strcmp(inst->type_out, type) != 0) {
		return true;
	}
	bool res = file_sink_write_packet(inst->fo, buf, length);
	if (!res) {
		log_error("Failed to write to packet sink");
	}
	return res;
}

static bool io_intf_send_relay(struct io_intf *inst, const char *type, const char *remote, const void *buf, const size_t length)
{
	bool res = relay_client_send_packet(&inst->ro, type, remote, buf, length);
	if (!res) {
		log_error("Failed to write to relay sink");
	}
	return res;
}

bool io_intf_send(struct io_intf *inst, const char *type, const char *remote, const void *buf, const size_t length)
{
	switch (inst->fmto) {
	case io_null: return true;
	case io_raw: return io_intf_send_raw(inst, type, buf, length);
	case io_packet: return io_intf_send_packet(inst, type, buf, length);
	case io_relay: return io_intf_send_relay(inst, type, remote, buf, length);
	}
	return NULL;
}

bool io_intf_forward(struct io_intf *inst, const struct relay_packet *data)
{
	/* log_info("Forwarding '%s' local='%s' remote='%s'", data->type, data->local, data->remote); */
	switch (inst->fmto) {
	case io_relay: return relay_client_send_packet2(&inst->ro, data);
	default: return io_intf_send(inst, data->type, data->remote, data->data, data->length);
	}
	return false;
}

void io_intf_destroy(struct io_intf *inst)
{
	relay_client_destroy(&inst->ri);
	relay_client_destroy(&inst->ro);
}

static enum io_handler_result handle_packet(struct io_intf *inst, const struct relay_packet *rp, const struct io_handler *begin, const struct io_handler *end)
{
	if (!streq_w(inst->local, rp->local)) {
		return iohr_ignore;
	}
	const struct io_handler *handler;
	for (handler = begin; handler != end; handler++) {
		if (streq_wl(handler->type, rp->type)) {
			switch (handler->func(inst, rp, handler->arg)) {
			case iohr_ignore: break;
			case iohr_handled: return iohr_handled;
			case iohr_consumed: return iohr_consumed;
			case iohr_terminate: return iohr_terminate;
			}
		}
	}
	return iohr_ignore;
}

bool io_intf_handle(struct io_intf *inst, const struct io_handler handlers[], size_t handler_count)
{
	struct relay_packet *rp = io_intf_recv(inst);
	if (!rp) {
		return false;
	}
	switch (handle_packet(inst, rp, handlers, handlers + handler_count)) {
	case iohr_ignore: break;
	case iohr_handled: break;
	case iohr_consumed:
		free(rp);
		return true;
	case iohr_terminate:
		free(rp);
		return false;
	}
	/*
	 * If output is socket to relay server, do not forward foreign
	 * packets.  This is to avoid looping our input back out.
	 */
	const bool out_is_relay_socket = inst->fmto == io_relay && inst->has_so && S_ISSOCK(inst->so.st_mode);
	if (out_is_relay_socket && rp->foreign) {
		/* log_info("Not forwarding foreign packet of type '%s' from '%s'", rp->type, rp->remote); */
	} else {
		io_intf_forward(inst, rp);
	}
	free(rp);
	return true;
}

void io_intf_loop(struct io_intf *inst, const struct io_handler handlers[], size_t handler_count)
{
	while (io_intf_handle(inst, handlers, handler_count)) {
		/* Loop */
	}
}
