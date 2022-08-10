/**
 * @author joelai
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/syscall.h>

#ifdef WITH_PREF_EVENTS
#  include <linux/perf_event.h>
#endif

#include "priv.h"

static const char* _aloe_str_negative_lut[] = {
	"no", "negative", "n", "none", "null", "empty", "false", "failure",
	"lose", "lost", "loser", NULL
};

static const char* _aloe_str_positive_lut[] = {
	"yes", "affirmative", "positive", "y", "any", "true", "success",
	"get", "got", "found", "win", "winner", "good", NULL
};

const char **aloe_str_negative_lut = _aloe_str_negative_lut;
const char **aloe_str_positive_lut = _aloe_str_positive_lut;

const char* aloe_str_find(const char **lut, const char *val, size_t len) {
	const char **r;

	if (!val) return NULL;

	for (r = lut; *r; r++) {
		if (len) {
			if (strncasecmp(*r, val, len) == 0) return *r;
		} else {
			if (strcasecmp(*r, val) == 0) return *r;
		}
	}
	return NULL;
}

int aloe_str_endwith(const char *str, const char *suf) {
	int str_len, sur_len;

	return str && suf && (str_len = strlen(str)) >= (sur_len = strlen(suf)) &&
			strcmp(str + str_len - sur_len, suf) == 0;
}

int aloe_strtol(const char *s, char **e, int base, long *val) {
	long v = strtol(s, e, base);
	if (v == LONG_MIN || v == LONG_MAX) return -1;
	if (val) *val = v;
	return 0;
}

int aloe_strtoi(const char *s, char **e, int base, int *val) {
	long v = strtol(s, e, base);
	if (v == LONG_MIN || v == LONG_MAX) return -1;
	if (val) *val = (int)v;
	return 0;
}

int aloe_str_ctrl1(char *buf, int len) {
	int i;

	if (!buf) return 32;

	for (i = 0; i <= aloe_min(len - 2, 30); i++) buf[i] = i + 1;
	if (len - 1 > i) buf[i++] = 127;
	buf[i] = '\0';
	return i;
}

static const char _aloe_str_sep[] = " \r\n\t";
const char *aloe_str_sep = _aloe_str_sep;

int aloe_cli_tok(char *cli, int *argc, char **argv, const char *sep) {
	int argmax = *argc;

	if (!sep) sep = aloe_str_sep;
	_aloe_cli_tok(cli, *argc, argv, sep, argmax);
	return 0;
}

size_t aloe_strrspn(const void *buf, size_t sz, const char *ext) {
	size_t _sz = sz;

	while (_sz > 0 && (((char*)buf)[_sz - 1] == '\0'
			|| (ext && strchr(ext, ((char*)buf)[_sz - 1])))) {
		_sz--;
	}
	return sz - _sz;
}

size_t aloe_strip_end(const void *buf, size_t sz, const char *ext) {
	while (sz > 0) {
		if (((char*)buf)[sz - 1] == '\0' ||
				(ext && strchr(ext, ((char*)buf)[sz - 1]))) {
			sz--;
			continue;
		}
		break;
	}
	return sz;
}

size_t aloe_rinbuf_read(aloe_buf_t *buf, void *data, size_t sz) {
	size_t rw_sz, ret_sz;

	if (sz > buf->lmt) sz = buf->lmt;
	ret_sz = sz;

	// rinbuf max continuous readable size: min(lmt, (cap - pos))
	while ((rw_sz = aloe_min(sz, buf->cap - buf->pos)) > 0) {
		memcpy(data, (char*)buf->data + buf->pos, rw_sz);
		buf->pos = (buf->pos + rw_sz) % buf->cap;
		buf->lmt -= rw_sz;
		if (rw_sz >= sz) break;
		sz -= rw_sz;
		data = (char*)data + rw_sz;
	}
	return ret_sz;
}

size_t aloe_rinbuf_write(aloe_buf_t *buf, const void *data, size_t sz) {
	size_t rw_sz, ret_sz;

	ret_sz = aloe_min(sz, buf->cap - buf->lmt);

	// rinbuf max continuous writable position: wpos = ((pos + lmt) % cap)
	while ((rw_sz = aloe_min(sz, buf->cap - buf->lmt)) > 0) {
		int rw_pos = (buf->pos + buf->lmt) % buf->cap;
		if (rw_sz > buf->cap - rw_pos) rw_sz = buf->cap - rw_pos;
		memcpy((char*)buf->data + rw_pos, data, rw_sz);
		buf->lmt += rw_sz;
		if (rw_sz >= sz) break;
		sz -= rw_sz;
		data = (char*)data + rw_sz;
	}
	return ret_sz;
}

aloe_buf_t* aloe_buf_clear(aloe_buf_t *buf) {
	_aloe_buf_clear(buf);
	return buf;
}

aloe_buf_t* aloe_buf_flip(aloe_buf_t *buf) {
	_aloe_buf_flip(buf);
	return buf;
}

aloe_buf_t* aloe_buf_replay(aloe_buf_t *buf) {
	// sanity check
	if (buf->pos > buf->lmt) {
		log_e("Invalid pos > lmt\n");
		return buf;
	}
	_aloe_buf_replay(buf);
	return buf;
}

//aloe_buf_t* aloe_buf_shift_left(aloe_buf_t *buf, size_t offset) {
//	if (!buf->data || offset > buf->pos || buf->pos > buf->lmt) return buf;
//	memmove(buf->data, (char*)buf->data + offset, buf->pos - offset);
//	buf->pos -= offset;
//	buf->lmt -= offset;
//	return buf;
//}

int aloe_buf_expand(aloe_buf_t *buf, size_t cap, aloe_buf_flag_t retain) {
	void *data;

	if (cap <= 0 || buf->cap >= cap) return 0;
	if (!(data = malloc(cap))) return ENOMEM;
	if (buf->data) {
		if (retain == aloe_buf_flag_retain_rinbuf) {
			aloe_rinbuf_read(buf, data, buf->lmt);
			buf->pos = 0;
		} else if (retain == aloe_buf_flag_retain_index) {
			memcpy(data, (char*)buf->data, buf->pos);
			if (buf->lmt == buf->cap) buf->lmt = cap;
		}
		free(buf->data);
	} else if (retain == aloe_buf_flag_retain_index) {
		buf->lmt = cap;
	}
	buf->data = data;
	buf->cap = cap;
	return 0;
}

int aloe_buf_vprintf(aloe_buf_t *buf, const char *fmt, va_list va) {
	int r;

	r = vsnprintf((char*)buf->data + buf->pos, buf->lmt - buf->pos, fmt, va);
	if (r < 0 || r >= buf->lmt - buf->pos) return -1;
	buf->pos += r;
	return r;
}

int aloe_buf_printf(aloe_buf_t *buf, const char *fmt, ...) {
	int r;
	va_list va;

	if (!fmt) return 0;
	va_start(va, fmt);
	r = aloe_buf_vprintf(buf, fmt, va);
	va_end(va);
	return r;
}

int aloe_buf_vaprintf(aloe_buf_t *buf, ssize_t max, const char *fmt,
		va_list va) {
	int r;

	if (!fmt || !fmt[0]) return 0;

	if (max == 0 || buf->lmt != buf->cap) {
		return aloe_buf_vprintf(buf, fmt, va);
	}
	if (aloe_buf_expand(buf, ((max > 0 && max < 32) ? max : 32),
			aloe_buf_flag_retain_index) != 0) {
		return -1;
	}

	while (1) {
		va_list vb;

#if __STDC_VERSION__ < 199901L
#  warning "va_copy() may require C99"
#endif
		va_copy(vb, va);
		r = aloe_buf_vprintf(buf, fmt, vb);
		if (r < 0 || r >= buf->cap) {
			if (max > 0 && buf->cap >= max) return -1;
			r = buf->cap * 2;
			if (max > 0 && r > max) r = max;
			if (aloe_buf_expand(buf, r, aloe_buf_flag_retain_index) != 0) {
				va_end(vb);
				return -1;
			}
			va_end(vb);
			continue;
		}
		va_end(vb);
		return r;
	};
}

int aloe_buf_aprintf(aloe_buf_t *buf, ssize_t max, const char *fmt, ...) {
	int r;
	va_list va;

	if (!fmt) return 0;
	va_start(va, fmt);
	r = aloe_buf_vaprintf(buf, max, fmt, va);
	va_end(va);
	return r;
}

aloe_buf_t* aloe_buf_strip_text(aloe_buf_t *buf) {
	char spn[aloe_str_ctrl1(NULL, 0) + 8]; // space and ctrl
	int r;

	// assume buf contain string buf->lmt point to trailing zero
	if (buf->lmt >= buf->cap || ((char*)buf->data)[buf->lmt]) return NULL;

	if (buf->pos >= buf->lmt) return buf;

	// strip trailing whitespace
	r = aloe_strrspn((char*)buf->data + buf->pos,
			buf->lmt - buf->pos, aloe_str_sep);
	if (r > 0) {
		((char*)buf->data)[buf->lmt -= r] = '\0';
		if (buf->pos >= buf->lmt) return buf;
	}

	// strip leading whitespace and ctrl chars
	spn[0] = ' ';
	aloe_str_ctrl1(&spn[1], sizeof(spn) - 1);
	buf->pos += strspn((char*)buf->data + buf->pos, spn);
	if (buf->pos >= buf->lmt) return buf;
	return buf;
}

int aloe_log_lvl(const char *lvl) {
	int lvl_n = (int)(unsigned long)lvl;

	if (lvl_n == aloe_log_level_err
			|| lvl_n == aloe_log_level_info
			|| lvl_n == aloe_log_level_debug
			|| lvl_n == aloe_log_level_verb) {
		return lvl_n;
	}
	if (strncasecmp(lvl, "err", strlen("err")) == 0) return aloe_log_level_err;
	if (strncasecmp(lvl, "inf", strlen("inf")) == 0) return aloe_log_level_info;
	if (strncasecmp(lvl, "deb", strlen("deb")) == 0) return aloe_log_level_debug;
	if (strncasecmp(lvl, "ver", strlen("ver")) == 0) return aloe_log_level_verb;
	return 0;
}

const char *aloe_log_lvl_str(const char *lvl) {
	int lvl_n = (int)(unsigned long)lvl;

	if (lvl_n == aloe_log_level_err) return "ERROR";
	else if (lvl_n == aloe_log_level_info) return "INFO";
	else if (lvl_n == aloe_log_level_debug) return "Debug";
	else if (lvl_n == aloe_log_level_verb) return "verbose";
	else if (lvl && lvl[0]) return lvl;
	return "";
}

__attribute__((format(printf, 5, 0)))
int aloe_log_vsnprintf(aloe_buf_t *fb, const char *lvl, const char *func_name,
		int lno, const char *fmt, va_list va) {
	int r, pos0 = (int)fb->pos;

	{
		struct timespec ts;
		struct tm tm;

		clock_gettime(CLOCK_REALTIME, &ts);
		localtime_r(&ts.tv_sec, &tm);

		if ((r = aloe_buf_printf(fb, "[%02d:%02d:%02d:%06d]", tm.tm_hour,
				tm.tm_min, tm.tm_sec, (int)(ts.tv_nsec / 1000))) <= 0) {
			r = -1;
			goto finally;
		}
	}

	{
		if ((r = aloe_buf_printf(fb, "[%s]", aloe_log_lvl_str(lvl))) <= 0) {
			r = -1;
			goto finally;
		}
	}

	{
		if ((r = aloe_buf_printf(fb, "[%s][#%d]", func_name, lno)) <= 0) {
			r = -1;
			goto finally;
		}
	}

	if ((r = vsnprintf((char*)fb->data + fb->pos, fb->lmt - fb->pos, fmt,
			va)) <= 0) {
		r = -1;
		goto finally;
	}
	if (fb->pos + r >= fb->lmt) {
#if 1
		// apply ellipsis
		const char ellipsis[] = "...\r\n";
		int len = (int)strlen(ellipsis);

		if (len < fb->lmt) {
			memcpy((char*)fb->data + fb->lmt - 1 - len, ellipsis, len + 1);
			fb->pos = fb->lmt - 1;
			r = 0;
			goto finally;
		}
#endif
		r = -1;
		goto finally;
	}
	fb->pos += r;
	r = 0;
finally:
	return r == 0 ? fb->pos - pos0 : 0;
}

__attribute__((format(printf, 5, 6)))
int aloe_log_snprintf(aloe_buf_t *fb, const char *lvl, const char *func_name,
		int lno, const char *fmt, ...) {
	int r;
	va_list va;

	va_start(va, fmt);
	r = aloe_log_vsnprintf(fb, lvl, func_name, lno, fmt, va);
	va_end(va);
	return r;
}

__attribute__((format(printf, 4, 5)))
int aloe_log_printf_std(const char *lvl, const char *func_name, int lno,
		const char *fmt, ...) {
#if 0
	return 0;
#else
	char buf[500];
	aloe_buf_t fb = {.data = buf, .cap = sizeof(buf)};
	int r, lvl_n = aloe_log_lvl(lvl);
	FILE *fp;
	va_list va;

	fp = ((lvl_n >= aloe_log_level_info) ? stderr : stdout);

	aloe_buf_clear(&fb);
	va_start(va, fmt);
	r = aloe_log_vsnprintf(&fb, lvl, func_name, lno, fmt, va);
	va_end(va);
	if ((r <= 0)) return 0;
	aloe_buf_flip(&fb);
	if (fb.lmt > 0) {
		fwrite(fb.data, 1, fb.lmt, fp);
		fflush(fp);
	}
	return fb.lmt;
#endif
}

__attribute__((format(printf, 4, 5), weak, alias("aloe_log_printf_std")))
int aloe_log_printf(const char *lvl, const char *func_name, int lno,
		const char *fmt, ...) ;

ssize_t _aloe_file_size(const void *f, int is_fd) {
	struct stat st;
	int r;

	if (is_fd == 1) {
		r = fstat((int)(long)f, &st);
	} else {
		r = stat((char*)f, &st);
	}
	if (r == 0) return st.st_size;
	r = errno;
	if (r == ENOENT) return -2;
	return -1;
}

ssize_t aloe_file_size(const void *f, int is_fd) {
	int r = _aloe_file_size(f, is_fd);
	if (r >= 0) return r;
	if (r == -2) return 0;
	return -1;
}

ssize_t aloe_file_vfprintf2(const char *fname, const char *mode,
		const char *fmt, va_list va) {
	int r;
	FILE *fp = NULL;

	if (!fmt) return 0;
	if (!(fp = fopen(fname, mode))) {
		r = errno;
//		log_e("Failed open %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
	if ((r = vfprintf(fp, fmt, va)) < 0) {
		r = errno;
//		log_e("Failed write %s: %s\n", fname, strerror(r));
		r = -1;
		goto finally;
	}
	fflush(fp);
finally:
	if (fp) fclose(fp);
	return r;
}

ssize_t aloe_file_fprintf2(const char *fname, const char *mode,
		const char *fmt, ...) {
	va_list va;
	int r;

	va_start(va, fmt);
	r = aloe_file_vfprintf2(fname, mode, fmt, va);
	va_end(va);
	return r;
}

int aloe_file_fread(const char *fname, aloe_buf_t *buf) {
	int fd = -1, r, fsz, len;

	if (!buf->data || (len = buf->lmt - buf->pos) < 2
			|| (fsz = (int)aloe_file_size(fname, 0)) < 1) {
		return 0;
	}

	// reserve trailing zero
	len--;

	if (len > fsz) len = fsz;
	if ((fd = open(fname, O_RDONLY, 0666)) == -1) {
		r = errno;
		log_e("Failed open %s: %s\n", fname, strerror(r));
		return -1;
	}
	r = read(fd, (char*)buf->data + buf->pos, len);
	close(fd);
	if (r < 0) {
		r = errno;
		log_e("Failed read %s: %s\n", fname, strerror(r));
		return -1;
	}
	((char*)buf->data)[buf->pos += r] = '\0';
	if (r != len) {
		r = EIO;
		log_e("Incomplete read %s, %d / %d\n", fname, r, len);
		return -2;
	}
	return r;
}

int aloe_file_fwrite(const char *fname, aloe_buf_t *buf) {
	int fd = -1, r, len;

	if (!buf->data || (len = buf->lmt - buf->pos) <= 0) {
		return 0;
	}
	if ((fd = open(fname, O_CREAT|O_WRONLY|O_TRUNC, 0666)) == -1) {
		r = errno;
		log_e("Failed open %s: %s\n", fname, strerror(r));
		return -1;
	}
	r = write(fd, (char*)buf->data + buf->pos, len);
	close(fd);
	if (r < 0) {
		r = errno;
		log_e("Failed write %s: %s\n", fname, strerror(r));
		return -1;
	}
	if (r != len) {
		r = EIO;
		log_e("Incomplete write %s, %d / %d\n", fname, r, len);
		return -1;
	}
	return r;
}

int aloe_file_nonblock(int fd, int en) {
	int r;

	if ((r = fcntl(fd, F_GETFL, NULL)) == -1) {
		r = errno;
		log_e("Failed to get file flag: %s(%d)\n", strerror(r), r);
		return r;
	}
	if (en) r |= O_NONBLOCK;
	else r &= (~O_NONBLOCK);
	if ((r = fcntl(fd, F_SETFL, r)) != 0) {
		r = errno;
		log_e("Failed to set nonblocking file flag: %s(%d)\n", strerror(r), r);
		return r;
	}
	return 0;
}

int _aloe_file_stdout(const char *fname, FILE **sfp, int sfd) {
	int r, fd;

	if (sfp && *sfp) {
		FILE *f;

		if (!(f = freopen(fname, "a+", *sfp))) {
			r = errno;
//			log_e("Failed reopen %s, %s\n", fname, strerror(r));
			return -1;
		}
		if (*sfp != f) *sfp = f;
		fd = fileno(f);
	} else {
		if ((fd = open(fname, O_WRONLY | O_APPEND | O_CREAT, 0666)) == -1) {
			r = errno;
//			log_e("Failed open %s, %s\n", fname, strerror(r));
			return -1;
		}
		if (lseek(fd, 0, SEEK_END) == (off_t)-1) {
			r = errno;
//			log_e("Failed set position bottom to %s: %s\n", fname, strerror(r));
			close(fd);
			return -1;
		}
	}

	if (sfd != -1) {
		while (dup2(fd, sfd) == -1) {
			r = errno;
			if (r == EBUSY || r == EINTR) {
				usleep(rand() % 300);
				continue;
			}
			if (!sfp || !*sfp) close(fd);
//			log_e("Failed dup2 %s for #%d, %s\n", fname, sfd, strerror(r));
			return -1;
		}
	}
	return fd;
}

int aloe_ip_bind(struct sockaddr *sa, int cs) {
	int fd = -1, r, af = aloe_sockaddr_family(sa);
	socklen_t sa_len;

	switch (af) {
	case AF_INET:
		sa_len = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		sa_len = sizeof(struct sockaddr_in6);
		break;
	case AF_UNIX:
		sa_len = sizeof(struct sockaddr_un);
		break;
	default:
		log_e("Unknown socket type\n");
		return -1;
	}

	if ((fd = socket(af, cs, 0)) == -1) {
		r = errno;
		log_e("Failed create ip socket, %s(%d)\n", strerror(r), r);
		return -1;
	}
	if (af == AF_INET || af == AF_INET6) {
		r = 1;
		if ((r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &r, sizeof(r))) < 0) {
			r = errno;
			close(fd);
			log_e("Failed set ip socket reuseaddr, %s(%d)\n", strerror(r), r);
			return -1;
		}
	}
	if ((r = bind(fd, sa, sa_len)) < 0) {
		r = errno;
		close(fd);
		log_e("Failed bind ip socket, %s(%d)\n", strerror(r), r);
		return -1;
	}
	return fd;
}

int aloe_ip_listener(struct sockaddr *sa, int cs, int backlog) {
	int fd = -1, r;

	if ((fd = aloe_ip_bind(sa, cs)) == -1) return -1;
	if ((r = listen(fd, backlog)) < 0) {
		r = errno;
		close(fd);
		log_e("Failed listen ip socket, %s(%d)\n", strerror(r), r);
		return -1;
	}
	return fd;
}

int aloe_ip_str(struct sockaddr *sa, aloe_buf_t *buf, unsigned flag) {
	if (sa->sa_family == AF_INET) {
		if (flag & aloe_ip_str_addr) {
			if (!inet_ntop(AF_INET, &((struct sockaddr_in*)sa)->sin_addr,
					(char*)buf->data + buf->pos,
					(socklen_t)buf->lmt - buf->pos - 1)) {
				return -1;
			}
			buf->pos += strlen((char*)buf->data + buf->pos);
		}
		if (flag & aloe_ip_str_port) {
			if (aloe_buf_printf(buf, ":%d",
					ntohs(((struct sockaddr_in*)sa)->sin_port)) <= 0) {
				return -1;
			}
		}
		return 0;
	}
	if (sa->sa_family == AF_INET6) {
		if (flag & aloe_ip_str_addr) {
			if (!inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa)->sin6_addr,
					(char*)buf->data + buf->pos,
					(socklen_t)buf->lmt - buf->pos - 1)) {
				return -1;
			}
			buf->pos += strlen((char*)buf->data + buf->pos);
		}
		if (flag & aloe_ip_str_port) {
			if (aloe_buf_printf(buf, ":%d",
					ntohs(((struct sockaddr_in6*)sa)->sin6_port)) <= 0) {
				return -1;
			}
		}
		return 0;
	}
	return -1;
}

int aloe_accessory_name_refine(aloe_buf_t *buf) {
	char spn[aloe_str_ctrl1(NULL, 0) + 8]; // space and ctrl

	// strip trailing whitespace
	((char*)buf->data)[buf->lmt -= aloe_strrspn((char*)buf->data + buf->pos,
			buf->lmt - buf->pos, aloe_str_sep)] = '\0';
	if (buf->pos >= buf->lmt) return -1;

	// strip leading whitespace and ctrl chars
	spn[0] = ' ';
	aloe_str_ctrl1(&spn[1], sizeof(spn) - 1);
	buf->pos += strspn((char*)buf->data + buf->pos, spn);
	if (buf->pos >= buf->lmt) return -1;

	// filter valid character
	((char*)buf->data)[(buf->lmt = buf->pos + strcspn(
			(char*)buf->data + buf->pos, spn + 1))] = '\0';
	if (buf->pos >= buf->lmt) return -1;
	return 0;
}

int aloe_hostname_refine(aloe_buf_t *buf) {
	char *c, *t;

	for (c = (char*)buf->data + buf->pos, t = (char*)buf->data + buf->lmt;
			c < t; c++) {
		if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z')
				|| (*c >= '0' && *c <= '9'))) {
			*c = '_';
		}
	}
	return 0;
}

int aloe_hostname_get(aloe_buf_t *buf) {
	if (buf && !buf->data && aloe_buf_expand(buf, HOST_NAME_MAX,
			aloe_buf_flag_retain_index) != 0) {
		log_e("Failed alloc memory for host name\n");
		return -1;
	}
	if (buf->data && buf->lmt - buf->pos > 0) {
		return gethostname((char*)buf->data + buf->pos, buf->lmt - buf->pos);
	}
	log_e("Invalid buffer for host name\n");
	return -1;
}

int aloe_hostname_set(const char *fn_cfg, aloe_buf_t *buf) {
	int r;

	if (fn_cfg && (r = aloe_file_fwrite(fn_cfg, buf)) != (buf->lmt - buf->pos)) {
		r = EIO;
		log_e("Save hostname to %s\n", fn_cfg);
		goto finally;
	}
	if ((r = sethostname((char*)buf->data + buf->pos, buf->lmt - buf->pos)) != 0) {
		r = errno;
		log_e("Set hostname %s, %s\n", (char*)buf->data + buf->pos, strerror(r));
		goto finally;
	}
	log_d("Set hostname: %s\n", (char*)buf->data + buf->pos);
	r = 0;
finally:
	return r;
}

int aloe_hostname_printf(const char *fn_cfg, const char *fmt, ...) {
	int r;
	aloe_buf_t buf = {0};
	va_list va;

	va_start(va, fmt);
	r = aloe_buf_vaprintf(&buf, -1, fmt, va);
	va_end(va);
	if (r <= 0) {
		r = ENOMEM;
		log_e("No memory for host name\n");
		goto finally;
	}
	aloe_buf_flip(&buf);
	aloe_hostname_refine(&buf);
	r = aloe_hostname_set(fn_cfg, &buf);
finally:
	if (buf.data) free(buf.data);
	return r;
}

#if defined(WITH_PREF_EVENTS)

typedef struct {
	int fd, st;
} perfev_t;

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags) {
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

void* aloe_perfev_init(void) {
	struct perf_event_attr pe;
	perfev_t *pfe = NULL;
	int r;

	if ((pfe = malloc(sizeof(*pfe))) == NULL) {
		r = ENOMEM;
		log_e("Allocate memory for context\n");
		goto finally;
	}
	pfe->fd = -1;
	pfe->st = 0;

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_HARDWARE;
	pe.size = sizeof(pe);
	pe.config = PERF_COUNT_HW_CPU_CYCLES;
	pe.disabled = 1;
//	pe.exclude_kernel = 1;
//	pe.exclude_hv = 1;

	if ((pfe->fd = perf_event_open(&pe, 0, -1, -1,
			PERF_FLAG_FD_NO_GROUP)) == -1) {
		r = errno;
		log_e("Open perf events: %s\n", strerror(r));
		goto finally;
	}
	r = 0;
finally:
	if (r != 0) {
		aloe_perfev_destroy(pfe);
		return NULL;
	}
	return pfe;
}

void aloe_perfev_destroy(void *ctx) {
	perfev_t *pfe = (perfev_t*)ctx;

	if (pfe) {
		if (pfe->fd != -1) close(pfe->fd);
		free(pfe);
	}
}

long long aloe_perfev_enable(void *ctx, int sw) {
	perfev_t *pfe = (perfev_t*)ctx;

	if (!sw) {
		long long count;

		ioctl(pfe->fd, PERF_EVENT_IOC_DISABLE, 0);
		read(pfe->fd, &count, sizeof(count));
		return count;
	}
	ioctl(pfe->fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(pfe->fd, PERF_EVENT_IOC_ENABLE, 0);
	return 0;
}

#endif
