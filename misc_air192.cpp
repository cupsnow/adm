/**
 * @author joelai
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/random.h>
#include <mqueue.h>
#include <pthread.h>

#include "priv.h"
#include <admin/air192.h>

#define APPCFG "/etc/sa7715.json"

extern "C"
int air192_name_get(const char **fns, aloe_buf_t *buf,
		int (*refine)(aloe_buf_t*)) {
	int r, fnidx = 0;
	const char *fn;

	if (!fns) {
		const char *_fns[] = {
				accname_cfg,
				hostname_cfg,
				"/etc/hostname-template",
				NULL
		};
		fns = _fns;
	}

	for (fnidx = 0; (fn = fns[fnidx]); fnidx++) {
		if (!*fn) continue;
		aloe_buf_t buf2 = {.data = (char*)buf->data + buf->pos,
				.cap = buf->lmt - buf->pos};
		if (aloe_file_fread(fn, aloe_buf_clear(&buf2)) < 1) continue;
		aloe_buf_flip(&buf2);
		// refine will modify buf2
		if (refine && (*refine)(&buf2) != 0) continue;
		if (buf2.pos >= buf2.lmt) continue;
		if (buf2.pos > 0) {
			memmove(buf2.data, (char*)buf2.data + buf2.pos, buf2.lmt - buf2.pos);
		}
		((char*)buf->data)[buf->pos += (buf2.lmt - buf2.pos)] = '\0';
		return 0;
	}
	if ((r = gethostname((char*)buf->data + buf->pos,
			buf->lmt - buf->pos)) != 0) {
		r = errno;
		log_e("Failed get hostname: %s\n", strerror(r));
		return -1;
	}
	((char*)buf->data)[buf->pos += strlen((char*)buf->data + buf->pos)] = '\0';
	return 0;
}

extern "C"
cJSON* air192_cfg_load(const char **fns, aloe_buf_t *buf) {
	aloe_buf_t _buf = {0};
	int r, fidx;
	const char *fn;
	cJSON *jroot;

	if (!buf) buf = &_buf;
	if (!fns) {
		const char *_fns[] = {
				APPCFG,
				NULL
		};
		fns = _fns;
	}
	for (fidx = 0; (fn = fns[fidx]); fidx++) {
		int fsz;

		if (!*fn || (fsz = aloe_file_size(fn, 0)) <= 0) continue;
		if (aloe_buf_expand(buf, aloe_padding2(fsz, 31), aloe_buf_flag_none) != 0) {
			r = ENOMEM;
			log_e("Failed malloc %d bytes\n", fsz + 8);
			goto finally;
		}
		if (aloe_file_fread(fn, aloe_buf_clear(buf)) != fsz) {
			r = EIO;
			log_e("Failed read config file %s\n", fn);
			goto finally;
		}
		aloe_buf_flip(buf);
		if (!(jroot = cJSON_ParseWithLengthOpts((char*)buf->data + buf->pos,
				buf->lmt - buf->pos, NULL, 0))) {
			r = EIO;
			log_e("Failed parse config file %s\n", fn);
			goto finally;
		}
		r = 0;
		goto finally;
	}
	r = EIO;
finally:
	if (_buf.data) free(_buf.data);
	return r == 0 ? jroot : NULL;
}

extern "C"
int air192_cfg_load2(const char **fns, aloe_buf_t *buf, int oob) {
	int fidx;
	const char *fn;

	for (fidx = 0; (fn = fns[fidx]); fidx++) {
		int fsz;

		if (!fn[0] || (fsz = aloe_file_size(fn, 0)) <= 0) continue;
		if (oob > 0 && fsz > oob) {
			log_e("Unexpected size %d > %d bytes for: %s\n", fsz, oob, fn);
			return -1;
		}
		if (aloe_buf_expand(buf, aloe_padding2(fsz, 31),
				aloe_buf_flag_none) != 0) {
			log_e("Out of memory to read %s\n", fn);
			return -1;
		}
		if (aloe_file_fread(fn, aloe_buf_clear(buf)) != fsz) {
			log_e("Failed read %s\n", fn);
			return -1;
		}
		log_d("Load %d bytes form %s\n", fsz, fn);
		return 0;
	}
	return -1;
}

extern "C"
uint16_t air192_eve_hash4(const void *data, size_t sz) {
	uint32_t hash32 = 2166136261;

	while (sz-- > 0) {
		hash32 = (hash32 ^ *(char*)data) * 16777619;
		data = (char*)data + 1;
	}
	return (uint16_t)((hash32 >> 16) ^ (hash32 & 0xFFFF));
}

extern "C"
int air192_GetSerialNumberHashString(const char *inSerialNumber,
		char *outHashStrBuf, int outHashStrBufSize) {
	if (inSerialNumber == NULL || outHashStrBuf == NULL
			|| outHashStrBufSize <= 4) // Reserved 1 byte of NULL character
	{
		return -1;
	}

	int len = (int)strlen(inSerialNumber);
	uint32_t hash32 = 2166136261;

	for (int i = 0; i < len; ++i) {
		hash32 = (hash32 ^ inSerialNumber[i]) * 16777619;
	}

	uint16_t hash = (hash32 >> 16) ^ (hash32 & 0xFFFF);
	if (snprintf(outHashStrBuf, outHashStrBufSize, "%04X", hash) != 4) {
		return -1;
	}
	return 0;
}

extern "C"
__attribute__((format(scanf, 2, 3)))
int air192_file_scanf1(const char *fname, const char *fmt, ...) {
	int r;
	FILE *fp = NULL;
	va_list va;

	if ((r = aloe_file_size(fname, 0)) == 0) return 0;
	if (!(fp = fopen(fname, "r"))) {
//		r = errno;
//		log_e("Failed open %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
	va_start(va, fmt);
	r = vfscanf(fp, fmt, va);
	va_end(va);
	if (r == EOF) {
//		r = errno;
//		log_f("Failed scanf %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
finally:
	if (fp) fclose(fp);
	return r;
}

extern "C"
int air192_regex_test1(const char *fmt, const char *pat, int cflags,
		size_t nmatch, regmatch_t *pmatch) {
	regex_t regex;
	int r;
	char err_msg[100];

	if ((r = regcomp(&regex, pat, cflags)) != 0) {
		regerror(r, &regex, err_msg, sizeof(err_msg));
		err_msg[sizeof(err_msg) - 1] = '\0';
		log_e("Compile regex pattern '%s', flag: %d, %s\n", pat, cflags, err_msg);
		return r;
	}

	if ((r = regexec(&regex, fmt, nmatch, pmatch, 0)) == 0) {
//		log_d("Matched string '%s' against '%s'\n", fmt, pat);
		regfree(&regex);
		return 0;
	}

	if (r != REG_NOMATCH) {
		regerror(r, &regex, err_msg, sizeof(err_msg));
		err_msg[sizeof(err_msg) - 1] = '\0';
		regfree(&regex);
		log_e("Failed match string '%s' against '%s': %s\n", fmt, pat, err_msg);
		return r;
	}
	regfree(&regex);
//	log_e("No matched string '%s' against '%s'\n", fmt, pat);
	return r;
}

extern "C"
__attribute__((format(printf, 3, 4)))
int air192_led_set(int led_val, unsigned long send_dur,
		const char *name_fmt, ...) {
	int r;
	mqd_t mq = (mqd_t)-1;
	air192_mqled_tlv_t msg;
	va_list va;

	va_start(va, name_fmt);
	r = vsnprintf(msg.mqled.name, sizeof(msg.mqled.name), name_fmt, va);
	va_end(va);
	if (r >= (int)sizeof(msg.mqled.name)) {
		r = EIO;
		log_e("too long for led name\n");
		goto finally;
	}
	msg.mqled.name_len = r + 1;
	msg.mqled.led_val = led_val;
	msg.tlvhdr.type = air192_mqled_tlvtype;
	msg.tlvhdr.len = offsetof(air192_mqled_t, name) + msg.mqled.name_len;

	if ((mq = mq_open(air192_mqled_name, O_WRONLY, 0644, NULL)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}
	if (send_dur != (unsigned long)-1) {
		struct timespec due;

		if ((r = clock_gettime(CLOCK_REALTIME, &due)) != 0) {
			r = errno;
			log_e("failed get time: %s\n", strerror(r));
			goto finally;
		}
		if (send_dur != 0) {
			ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, send_dur / 1000l,
					(send_dur % 1000l) * 1000000l,
					due.tv_sec, due.tv_nsec, 1000000000l);
		}
		r = mq_timedsend(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len,
				0, &due);
	} else {
		r = mq_send(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len, 0);
	}
	if (r != 0) {
		r = errno;
		log_e("send to mq: %s\n", strerror(r));
		goto finally;
	}
	log_d("sent to %s, led %s, val %d\n", air192_mqled_name, msg.mqled.name,
			msg.mqled.led_val);
	r = 0;
finally:
	if (mq != (mqd_t)-1) mq_close(mq);
	return r;
}

extern "C"
int air192_adk_paired(const char **fns) {
	int fidx;
	const char *fn;

	if (!fns) {
		const char *_fns[] = {
				persist_cfg "/hap-setupinfo/A0.00",
				"/root/.HomeKitStore/hap-setupinfo/A0.00",
				NULL
		};
		fns = _fns;
	}
	for (fidx = 0; (fn = fns[fidx]); fidx++) {
		int fsz;

		if (!fn[0] || (fsz = aloe_file_size(fn, 0)) > 0) return 1;
	}
	return 0;
}

extern "C"
__attribute__((format(printf, 3, 4)))
int air192_cgireq_open(air192_cgireq_t *req, const char *prog_lock,
		const char *fmt, ...) {
	int r;
	va_list va;
	const char *str;

	if (aloe_buf_expand(&req->cmdbuf, 500, aloe_buf_flag_none) != 0) {
		r = ENOMEM;
		req->err = -1;
		req->reason = "Out of memory";
		goto finally;
	}
	if (prog_lock) {
		r = air192_file_scanf1(prog_lock, "%d %d", &req->prog_st, &req->prog_iter);
		if (r == 0) {
			req->prog_st = req->prog_iter = air192_cgireq_prog_null;
		} else if (r == 1) {
			req->prog_iter = air192_cgireq_prog_null;
		} else if (r != 2) {
			req->err = -1;
			air192_cgireq_reason(req, "Runtime error: %s", "get progress");
			goto finally;
		}
		log_d("%s prog: %d, iter: %d\n", prog_lock, req->prog_st, req->prog_iter);

		if (req->prog_st >= air192_cgireq_prog_fatal) {
			r = EIO;
			req->err = -1;
			air192_cgireq_reason(req, "Fatal error");
			goto finally;
		}

		if (req->prog_st < air192_cgireq_prog_complete &&
				req->prog_st != air192_cgireq_prog_null) {
			r = EBUSY;
			req->err = req->prog_st;
			air192_cgireq_reason(req, "Busy");
			goto finally;
		}
	}

	// CONTENT_TYPE=application/json
	// CONTENT_LENGTH=12
	aloe_buf_clear(&req->cmdbuf);
	if (fmt) {
		va_start(va, fmt);
		r = aloe_buf_vprintf(&req->cmdbuf, fmt, va);
		va_end(va);
		if (r < 0) {
			r = ENOMEM;
			req->err = -1;
			air192_cgireq_reason(req, "Invalid request: %s", "header");
			goto finally;
		}
	} else {
		if (!(str = getenv("CONTENT_TYPE"))
				|| strcasecmp(str, "application/json") != 0
				|| !(str = getenv("CONTENT_LENGTH"))
				|| (r = strtol(str, NULL, 0)) <= 0
				|| r >= (int)req->cmdbuf.cap
				|| r != (int)fread(req->cmdbuf.data, 1, r, stdin)) {
			r = EINVAL;
			req->err = -1;
			air192_cgireq_reason(req, "Invalid request: %s", "header");
			goto finally;
		}
		req->cmdbuf.pos += r;
	}
	aloe_buf_flip(&req->cmdbuf);

	log_d("received request: %d,\n%s\n", (int)req->cmdbuf.lmt, (char*)req->cmdbuf.data);

	if (!(req->jroot = cJSON_Parse((char*)req->cmdbuf.data))) {
		r = EINVAL;
		req->err = -1;
		air192_cgireq_reason(req, "Invalid request: %s", "JSON");
		goto finally;
	}
//	if (!(jobj = cJSON_GetObjectItem(req->jroot, "command"))
//			|| !(str = cJSON_GetStringValue(jobj))) {
//		r = -1;
//		air192_cgireq_reason(req, "Invalid request: %s", "command");
//		goto finally;
//	}
finally:
	return r;
}

extern "C"
__attribute__((format(printf, 4, 5)))
int air192_sus_set(int whence, int delay, unsigned long send_dur,
		const char *name_fmt, ...) {
	int r;
	mqd_t mq = (mqd_t)-1;
	air192_mqsus_tlv_t msg;
	va_list va;

	va_start(va, name_fmt);
	r = vsnprintf(msg.mqsus.name, sizeof(msg.mqsus.name), name_fmt, va);
	va_end(va);
	if (r >= (int)sizeof(msg.mqsus.name)) {
		r = EIO;
		log_e("too long for sus name\n");
		goto finally;
	}
	msg.mqsus.name_len = r + 1;
	msg.mqsus.whence = whence;
	msg.mqsus.delay = delay;
	msg.tlvhdr.type = air192_mqsus_tlvtype;
	msg.tlvhdr.len = offsetof(air192_mqsus_t, name) + msg.mqsus.name_len;

	if ((mq = mq_open(air192_mqsus_name, O_WRONLY, 0644, NULL)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}
	if (send_dur != (unsigned long)-1) {
		struct timespec due;

		if ((r = clock_gettime(CLOCK_REALTIME, &due)) != 0) {
			r = errno;
			log_e("failed get time: %s\n", strerror(r));
			goto finally;
		}
		if (send_dur != 0) {
			ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, send_dur / 1000l,
					(send_dur % 1000l) * 1000000l,
					due.tv_sec, due.tv_nsec, 1000000000l);
		}
		r = mq_timedsend(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len,
				0, &due);
	} else {
		r = mq_send(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len, 0);
	}
	if (r != 0) {
		r = errno;
		log_e("send to mq: %s\n", strerror(r));
		goto finally;
	}
	log_d("sent to %s, sender %s, whence %d, delay %d\n", air192_mqsus_name,
			msg.mqsus.name, msg.mqsus.whence, msg.mqsus.delay);
	r = 0;
finally:
	if (mq != (mqd_t)-1) mq_close(mq);
	return r;
}

static const char mqcli_prename[] = air192_mqcli_name_prefix;
#define mqcli_prename_sz (sizeof(mqcli_prename) - 1)

typedef struct {
	int quit;
	pthread_t thread;
	void *ev_ctx;

	void *ev_mq;
	mqd_t mq;
	aloe_buf_t recv_fb_mq;
	const char *name_mq;
	air192_cli_cb_t clicb;
	void *clicbarg;

	void *ev_mgr;
	int pipe_mgr[2];
	aloe_buf_t recv_fb_mgr;

} air192_cli_conn_t;

static void* air192_cli_thread(void *_conn) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)_conn;

	log_d("%s started\n", conn->name_mq);
	while (!conn->quit) {
    	aloe_ev_once(conn->ev_ctx);
	}
	log_d("%s stopped\n", conn->name_mq);
	return NULL;
}

static void air192_climgr_on_read(int fd, unsigned ev_noti, void *cbarg) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)cbarg;
	aloe_buf_t *fb = &conn->recv_fb_mgr;
	air192_tlvhdr_t *tlvhdr;
	int r;
	unsigned long tv_ms = ALOE_EV_INFINITE;

	if (ev_noti & aloe_ev_flag_read) {
		if (fb->lmt - fb->pos < sizeof(tlvhdr)) {
			log_e("unexpected receive buffer size\n");
			aloe_buf_clear(fb);
		}

		if ((r = read(conn->pipe_mgr[0], (char*)fb->data + fb->pos,
				fb->lmt - fb->pos)) < 0) {
			r = errno;
			log_e("Failed read air192 cli mgr: %s\n", strerror(r));
			goto finally;
		}
		fb->pos += r;

		aloe_buf_flip(fb);

		for (tlvhdr = (air192_tlvhdr_t*)((char*)fb->data + fb->pos);
				fb->lmt - fb->pos >= sizeof(*tlvhdr)
						&& fb->lmt - fb->pos >= sizeof(*tlvhdr) + tlvhdr->len;
				fb->pos += (sizeof(*tlvhdr) + tlvhdr->len),
						tlvhdr = (air192_tlvhdr_t*)((char*)fb->data + fb->pos)) {
			// sanity check
			if (tlvhdr->type != air192_climgr_tlvtype) {
				log_e("unexpected climgr\n");
				continue;
			}

			if (tlvhdr->len > 0 && ((char*)(tlvhdr + 1))[tlvhdr->len - 1] == '\0') {
				// assume string message
				log_d("%s %s recv %s\n", conn->name_mq, "climgr", (char*)(tlvhdr + 1));
			} else {
				log_d("%s %s recv %d bytes\n", conn->name_mq, "climgr", tlvhdr->len);
			}
		}
		aloe_buf_replay(fb);
		if (fb->pos > 0) log_d("remain %d bytes\n", (int)fb->pos);
	}
	r = 0;
finally:
	if (r == 0) {
		if ((conn->ev_mgr = aloe_ev_put(conn->ev_ctx, conn->pipe_mgr[0],
				&air192_climgr_on_read, conn, aloe_ev_flag_read,
				((tv_ms == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE : tv_ms / 1000ul),
				((tv_ms == ALOE_EV_INFINITE) ? 0 : (tv_ms % 1000ul) * 1000ul)))) {
			return;
		}
		log_e("Failed schedule air192 cli\n");
	}
}

static int air192_climgr_send_tlv(air192_cli_conn_t *conn,
		const air192_tlvhdr_t *tlvhdr) {
	aloe_buf_t fb = {.data = (void*)tlvhdr, .cap = sizeof(*tlvhdr) + tlvhdr->len};
	int r;

	aloe_buf_clear(&fb);
	while (fb.pos < fb.lmt) {
		if ((r = write(conn->pipe_mgr[1], (char*)fb.data + fb.pos,
				fb.lmt - fb.pos)) <= 0) {
			log_e("Failed notify air192 cli mgr\n");
			return r;
		}
		fb.pos += r;
	}
	return 0;
}

__attribute__((format(printf, 2, 3)))
static int air192_climgr_send_msg(air192_cli_conn_t *conn,
		const char *fmt, ...) {
	struct __attribute__((packed)) {
		air192_tlvhdr_t tlvhdr;
		char msg[80];
	} pkg;
	int r;
	va_list va;

	va_start(va, fmt);
	r = vsnprintf(pkg.msg, sizeof(pkg.msg), fmt, va);
	va_end(va);
	if (r >= (int)sizeof(pkg.msg)) {
		log_e("Too large for cli mgr\n");
		return EIO;
	}
	pkg.tlvhdr.type = air192_climgr_tlvtype;
	pkg.tlvhdr.len = r + 1;
	return air192_climgr_send_tlv(conn, &pkg.tlvhdr);
}

static void air192_cli_on_read(int fd, unsigned ev_noti, void *cbarg) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)cbarg;
	aloe_buf_t *fb = &conn->recv_fb_mq;
	air192_mqcli_tlv_t *msg;
	int r;
	unsigned long tv_ms = ALOE_EV_INFINITE;

	if (ev_noti & aloe_ev_flag_read) {
		if (fb->lmt - fb->pos < sizeof(msg)) {
			log_e("unexpected receive buffer size\n");
			aloe_buf_clear(fb);
		}

		if ((r = mq_receive(conn->mq, (char*)fb->data + fb->pos,
				fb->lmt - fb->pos, NULL)) < 0) {
			r = errno;
			log_e("Failed read air192 cli event: %s\n", strerror(r));
			goto finally;
		}
		fb->pos += r;

		aloe_buf_flip(fb);

		for (msg = (air192_mqcli_tlv_t*)((char*)fb->data + fb->pos);
				fb->lmt - fb->pos >= sizeof(msg->tlvhdr)
						&& fb->lmt - fb->pos >= sizeof(msg->tlvhdr) + msg->tlvhdr.len;
				fb->pos += (sizeof(msg->tlvhdr) + msg->tlvhdr.len),
						msg = (air192_mqcli_tlv_t*)((char*)fb->data + fb->pos)) {
			// sanity check
			if (msg->mqcli.name_len < 1
					|| msg->mqcli.name_len >= (int)sizeof(msg->mqcli.msg)
					|| msg->mqcli.msg[msg->mqcli.name_len - 1]
					|| msg->tlvhdr.type != air192_mqcli_tlvtype) {
				log_e("unexpected mqcli\n");
				continue;
			}

			log_d("%s recv: %s\n", conn->name_mq, msg->mqcli.msg);
			if (conn->clicb) {
				conn->clicb(conn->clicbarg, msg->mqcli.name_len - 1, msg->mqcli.msg);
			}
		}
		aloe_buf_replay(fb);
		if (fb->pos > 0) log_d("remain %d bytes\n", (int)fb->pos);
	}
	r = 0;
finally:
	if (r == 0) {
		if ((conn->ev_mq = aloe_ev_put(conn->ev_ctx, (int)conn->mq,
				&air192_cli_on_read, conn, aloe_ev_flag_read,
				((tv_ms == ALOE_EV_INFINITE) ? ALOE_EV_INFINITE : tv_ms / 1000ul),
				((tv_ms == ALOE_EV_INFINITE) ? 0 : (tv_ms % 1000ul) * 1000ul)))) {
			return;
		}
		log_e("Failed schedule air192 cli\n");
	}
}

extern "C"
void* air192_cli_start(const char *name, air192_cli_cb_t cb, void *cbarg) {
	int name_sz = strlen(name), msg_sz = sizeof(air192_mqcli_tlv_t),
			mgrmsg_sz = 150, r;
	air192_cli_conn_t *conn = NULL;
	struct mq_attr mqattr;
	char *ctr;

	if (!(conn = (air192_cli_conn_t*)malloc(sizeof(*conn)
			+ mqcli_prename_sz + name_sz + 1
			+ msg_sz * 2
			+ mgrmsg_sz))) {
		r = ENOMEM;
		log_e("no memory for air192_cli\n");
		goto finally;
	}
	memset(conn, 0, sizeof(*conn));
	conn->mq = (mqd_t)-1;
	conn->pipe_mgr[0] = conn->pipe_mgr[1] = -1;
	if (!(conn->ev_ctx = aloe_ev_init())) {
		r = ENOMEM;
		log_e("no memory for event proc\n");
		goto finally;
	}

	conn->name_mq = ctr = (char*)(conn + 1);
	memcpy(ctr, mqcli_prename, mqcli_prename_sz);
	memcpy(ctr + mqcli_prename_sz, name, name_sz);
	ctr[mqcli_prename_sz + name_sz] = '\0';
	ctr += mqcli_prename_sz + name_sz + 1;

	memset(&mqattr, 0, sizeof(mqattr));
	mqattr.mq_maxmsg = 10;
	mqattr.mq_msgsize = msg_sz;
	if ((conn->mq = mq_open(conn->name_mq, O_CREAT | O_RDONLY, 0644,
			&mqattr)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}

	if ((r = aloe_file_nonblock((int)conn->mq, 1)) != 0) {
		log_e("failed set nonblock for mq: %s\n", strerror(r));
		goto finally;
	}

	if (!(conn->ev_mq = aloe_ev_put(conn->ev_ctx, (int)conn->mq,
			&air192_cli_on_read, conn, aloe_ev_flag_read, ALOE_EV_INFINITE, 0))) {
		r = EIO;
		log_e("Failed schedule air192 cli\n");
		goto finally;
	}

	if (pipe(conn->pipe_mgr) != 0) {
		r = errno;
		log_e("Failed create air192 cli mgr pipe\n");
		goto finally;
	}

	if ((r = aloe_file_nonblock(conn->pipe_mgr[0], 1)) != 0) {
		log_e("failed set nonblock for mgr pipe: %s\n", strerror(r));
		goto finally;
	}

	if (!(conn->ev_mgr = aloe_ev_put(conn->ev_ctx, conn->pipe_mgr[0],
			&air192_climgr_on_read, conn, aloe_ev_flag_read, ALOE_EV_INFINITE, 0))) {
		r = EIO;
		log_e("Failed schedule air192 cli\n");
		goto finally;
	}

	conn->recv_fb_mq.data = ctr;
	conn->recv_fb_mq.cap = msg_sz * 2;
	aloe_buf_clear(&conn->recv_fb_mq);
	ctr += msg_sz * 2;

	conn->recv_fb_mgr.data = ctr;
	conn->recv_fb_mgr.cap = mgrmsg_sz;
	aloe_buf_clear(&conn->recv_fb_mgr);
	ctr += mgrmsg_sz;

	conn->clicb = cb;
	conn->clicbarg = cbarg;

	if ((r = pthread_create(&conn->thread, NULL, &air192_cli_thread,
			conn)) != 0) {
		r = errno;
		log_e("air192 cli thread: %s\n", strerror(r));
		goto finally;
	}
	r = 0;
finally:
	if (r != 0) {
		if (conn) {
			if (conn->pipe_mgr[0] == -1) close(conn->pipe_mgr[0]);
			if (conn->pipe_mgr[1] == -1) close(conn->pipe_mgr[1]);
			if (conn->mq != (mqd_t)-1) mq_close(conn->mq);
			if (conn->ev_ctx) aloe_ev_destroy(conn->ev_ctx);
			free(conn);
		}
		return NULL;
	}
	return conn;
}

void air192_cli_stop(void *ctx) {
	air192_cli_conn_t *conn = (air192_cli_conn_t*)ctx;
	int r;

	conn->quit = 1;

//	conn->clicb = NULL;
//	air192_cli_send(conn->name_mq + mqcli_prename_sz, ALOE_EV_INFINITE, "terminate");

	air192_climgr_send_msg(conn, "terminate");

	if ((r = pthread_join(conn->thread, NULL)) != 0) {
		r = errno;
		log_e("Failed join air192 cli: %s\n", strerror(r));
		return;
	}
	if (conn->ev_ctx) aloe_ev_destroy(conn->ev_ctx);
	if (conn->pipe_mgr[0] == -1) close(conn->pipe_mgr[0]);
	if (conn->pipe_mgr[1] == -1) close(conn->pipe_mgr[1]);
	if (conn->mq != (mqd_t)-1) mq_close(conn->mq);
	free(conn);
}

extern "C"
__attribute__((format(printf, 3, 0)))
int air192_cli_vsend(const char *name, unsigned long send_dur,
		const char *fmt, va_list va) {
	int name_sz = strlen(name), r;
	char mqname[50];
	mqd_t mq = (mqd_t)-1;
	air192_mqcli_tlv_t msg;

	if (mqcli_prename_sz + name_sz >= (int)sizeof(mqname)) {
		r = EIO;
		log_e("name too long for air192 cli\n");
		goto finally;
	}

	r = vsnprintf(msg.mqcli.msg, sizeof(msg.mqcli.msg), fmt, va);
	if (r >= (int)sizeof(msg.mqcli.msg)) {
		r = EIO;
		log_e("too long for air192 cli\n");
		goto finally;
	}
	msg.mqcli.name_len = r + 1;
	msg.tlvhdr.type = air192_mqcli_tlvtype;
	msg.tlvhdr.len = offsetof(air192_mqcli_t, msg) + msg.mqcli.name_len;
	memcpy(mqname, mqcli_prename, mqcli_prename_sz);
	memcpy(mqname + mqcli_prename_sz, name, name_sz);
	mqname[mqcli_prename_sz + name_sz] = '\0';

	if ((mq = mq_open(mqname, O_WRONLY, 0644, NULL)) == (mqd_t)-1) {
		r = errno;
		log_e("failed open mq: %s\n", strerror(r));
		goto finally;
	}
	if (send_dur != (unsigned long)-1) {
		struct timespec due;

		if ((r = clock_gettime(CLOCK_REALTIME, &due)) != 0) {
			r = errno;
			log_e("failed get time: %s\n", strerror(r));
			goto finally;
		}
		if (send_dur != 0) {
			ALOE_TIMESEC_ADD(due.tv_sec, due.tv_nsec, send_dur / 1000l,
					(send_dur % 1000l) * 1000000l,
					due.tv_sec, due.tv_nsec, 1000000000l);
		}
		r = mq_timedsend(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len,
				0, &due);
	} else {
		r = mq_send(mq, (char*)&msg, sizeof(msg.tlvhdr) + msg.tlvhdr.len, 0);
	}
	if (r != 0) {
		r = errno;
		log_e("send to mq: %s\n", strerror(r));
		goto finally;
	}
	log_d("sent to %s, %s\n", mqname, msg.mqcli.msg);
	r = 0;
finally:
	if (mq != (mqd_t)-1) mq_close(mq);
	return r;
}

extern "C"
__attribute__((format(printf, 3, 4)))
int air192_cli_send(const char *name, unsigned long send_dur,
		const char *fmt, ...) {
	int r;
	va_list va;

	va_start(va, fmt);
	r = air192_cli_vsend(name, send_dur, fmt, va);
	va_end(va);
	return r;
}
