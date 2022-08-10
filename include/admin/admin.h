/**
 * @author joelai
 */

#ifndef PACKAGE_ADMIN_ADMIN_H_
#define PACKAGE_ADMIN_ADMIN_H_

/** @mainpage
 *
 * # Introduction
 *
 * - Namespace is aloe_ev.
 * - Hack to check class size when build time. Referenced from <a href="https://stackoverflow.com/a/53884709">here</a>
 *   > ```
 *   > char checker(int);
 *   > char checkSizeOfInt[sizeof(usart->ctrla)] = {checker(&checkSizeOfInt)};
 *   > ```
 *   > ```
 *   > note: expected 'int' but argument is of type 'char (*)[4]'
 *   > ```
 */

/** @defgroup ALOE
 * @brief aloe namespace
 *
 * @defgroup ALOE_MISC Miscellaneous
 * @ingroup ALOE
 * @brief Trivial operation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <errno.h>

//#include <sys/socket.h>
//#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

#include <sys/un.h>

#include "compat/openbsd/sys/tree.h"
#include "compat/openbsd/sys/queue.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup ALOE_EV_MISC
 * @{
 */

#define aloe_trex "🦖" /**< Trex. */
#define aloe_sauropod "🦕" /**< Sauropod. */
#define aloe_lizard "🦎" /**< Lizard. */
#define aloe_cr '\r' // 0xd
#define aloe_lf '\n' // 0xa
#define aloe_endl_msw "\r\n"
#define aloe_endl_unix "\n"

#define aloe_min(_a, _b) ((_a) <= (_b) ? (_a) : (_b))
#define aloe_max(_a, _b) ((_a) >= (_b) ? (_a) : (_b))
#define aloe_arraysize(_arr) (sizeof(_arr) / sizeof((_arr)[0]))

#define aloe_padding2(_n, _b) (((_n) + (_b)) & ~(_b))

/** Stringify. */
#define _aloe_stringify(_s) # _s

/** Stringify support macro expansion. */
#define aloe_stringify(_s) _aloe_stringify(_s)

/** Fetch container object from a containing member object. */
#define aloe_container_of(_obj, _type, _member) \
	((_type *)((_obj) ? ((char*)(_obj) - offsetof(_type, _member)) : NULL))

/** String concatenate. */
#define _aloe_concat(_s1, _s2) _s1 ## _s2

/** String concatenate support macro expansion. */
#define aloe_concat(_s1, _s2) _aloe_concat(_s1, _s2)

#ifdef __GNUC__
#define aloe_offsetof(_s, _m) offsetof(_s, _m)
#else
#define aloe_offsetof(_s, _m) (((_s*)NULL)->_m)
#endif

#define ALOE_FLAG_MASK(_group, _offset, _bits) \
		_group ## _mask_offset = _offset, \
		_group ## _mask_bits = _bits, \
		_group ## _mask = (((1 << (_bits)) - 1) << (_offset))

#define ALOE_FLAG(_group, _name, _val) \
	_group ## _name = ((_val) << _group ## _mask_offset)

#define aloe_str_stuff(_arr, ...) do { \
	snprintf(_arr, sizeof(_arr), __VA_ARGS__); \
	((char*)(_arr))[sizeof(_arr) - 1] = '\0'; \
} while(0)

extern const char **aloe_str_negative_lut;
extern const char **aloe_str_positive_lut;
const char* aloe_str_find(const char **lut, const char *val, size_t len);

int aloe_str_endwith(const char *str, const char *suf);

int aloe_strtol(const char *s, char **e, int base, long *val);
int aloe_strtoi(const char *s, char **e, int base, int *val);

/** Fill max ascii[1..31,127], always add trailing zero.
 *
 * @param buf
 * @param len The size of buf
 * @return
 *   - size of fill without trailing zero
 *   - size of full set when buf == NULL
 */
int aloe_str_ctrl1(char *buf, int len);

extern const char *aloe_str_sep; // " \r\n\t"

#define _aloe_cli_tok(_cli, _argc, _argv, _sep, _argmax) if ( \
		(((_argc) = 0) < (_argmax)) && \
		((_argv)[_argc] = strtok_r(_cli, _sep, &(_cli)))) { \
	for ((_argc)++; ((_argc) < (_argmax)) && \
			((_argv)[_argc] = strtok_r(NULL, _sep, &(_cli))); \
			(_argc)++); \
}
int aloe_cli_tok(char *cli, int *argc, char **argv, const char *sep);

size_t aloe_strrspn(const void *buf, size_t sz, const char *ext);

/** Retern size excluding ending zero and optional characters.
 *
 * @param buf Buffer address
 * @param sz Size of buffer
 * @param ext Optional excluding characters.
 * @return
 */
size_t aloe_strip_end(const void *buf, size_t sz, const char *ext);

/** Generic buffer holder. */
typedef struct aloe_buf_rec {
	void *data; /**< Memory pointer. */
	size_t cap; /**< Memory capacity. */
	size_t lmt; /**< Data size. */
	size_t pos; /**< Data start. */
} aloe_buf_t;

/**
 * fb.pos: Start of valid data
 * fb.lmt: Size of valid data
 *
 * @param fb
 * @param data
 * @param sz
 * @return
 */
size_t aloe_rinbuf_read(aloe_buf_t *buf, void *data, size_t sz);

/**
 * fb.pos: Start of spare
 * fb.lmt: Size of valid data
 *
 * @param fb
 * @param data
 * @param sz
 * @return
 */
size_t aloe_rinbuf_write(aloe_buf_t *buf, const void *data, size_t sz);

#define _aloe_buf_clear(_buf) do {(_buf)->lmt = (_buf)->cap; (_buf)->pos = 0;} while (0)
#define _aloe_buf_flip(_buf) do {(_buf)->lmt = (_buf)->pos; (_buf)->pos = 0;} while (0)
#define _aloe_buf_replay(_buf) do { \
	int remain; \
	if ((remain = (_buf)->lmt - (_buf)->pos) > 0) { \
		memmove((_buf)->data, (char*)(_buf)->data + (_buf)->pos, remain); \
	} \
	(_buf)->pos = remain; (_buf)->lmt = (_buf)->cap; \
} while(0);

aloe_buf_t* aloe_buf_clear(aloe_buf_t *buf);
aloe_buf_t* aloe_buf_flip(aloe_buf_t *buf);
aloe_buf_t* aloe_buf_replay(aloe_buf_t *buf);

//aloe_buf_t* aloe_buf_shift_left(aloe_buf_t *buf, size_t offset);

typedef enum aloe_buf_flag_enum {
	aloe_buf_flag_none = 0,
	aloe_buf_flag_retain_rinbuf,
	aloe_buf_flag_retain_index,
} aloe_buf_flag_t;

/**
 *
 * aloe_buf_flag_retain_pos will update lmt if lmt == cap
 *
 * @param buf
 * @param cap
 * @param retain
 * @return
 */
int aloe_buf_expand(aloe_buf_t *buf, size_t cap, aloe_buf_flag_t retain);

/**
 *
 * Update buf index when all fmt fulfill.
 *
 * @param buf
 * @param fmt
 * @param va
 * @return -1 when error or not fulfill formating, otherwise length to append
 */
int aloe_buf_vprintf(aloe_buf_t *buf, const char *fmt, va_list va)
		__attribute__((format(printf, 2, 0)));
int aloe_buf_printf(aloe_buf_t *buf, const char *fmt, ...)
		__attribute__((format(printf, 2, 3)));

/**
 *
 * Malloc with max and buf.lmt == cap
 *
 * @param buf
 * @param max
 * @param fmt
 * @param va
 * @return
 */
int aloe_buf_vaprintf(aloe_buf_t *buf, ssize_t max, const char *fmt,
		va_list va) __attribute__((format(printf, 3, 0)));
int aloe_buf_aprintf(aloe_buf_t *buf, ssize_t max, const char *fmt, ...)
		__attribute__((format(printf, 3, 4)));

aloe_buf_t* aloe_buf_strip_text(aloe_buf_t *buf);

#define aloe_log_level_err 1
#define aloe_log_level_info 2
#define aloe_log_level_debug 3
#define aloe_log_level_verb 4

int aloe_log_lvl(const char *lvl);
const char *aloe_log_lvl_str(const char *lvl);

__attribute__((format(printf, 5, 0)))
int aloe_log_vsnprintf(aloe_buf_t *fb, const char *lvl, const char *func_name,
		int lno, const char *fmt, va_list);

__attribute__((format(printf, 5, 6)))
int aloe_log_snprintf(aloe_buf_t *fb, const char *lvl, const char *func_name,
		int lno, const char *fmt, ...);

int aloe_log_printf(const char *lvl, const char *func_name, int lno,
		const char *fmt, ...);

//int aloe_syslog_lvl(const char *lvl);

#define syslog_m(_lvl, _fmt, _args...) syslog(_lvl, "[%s][#%d] " _fmt, __func__, __LINE__, ##_args)
#define syslog_e(_args...) syslog_m(LOG_ERR, ##_args)
#define syslog_d(_args...) syslog_m(LOG_DEBUG, ##_args)

typedef struct aloe_mod_rec {
	const char *name;
	void* (*init)(void);
	void (*destroy)(void*);
	int (*ioctl)(void*, void*);
} aloe_mod_t;

/**
 *
 * @param f
 * @param fd fd=1 if f is file descriptor, otherwise assume f is path
 * @return
 */
ssize_t aloe_file_size(const void *f, int is_fd);

/**
 *
 * @param f
 * @param fd
 * @return <br/>
 *   - >= 0 for file size
 *   - -2 when file missing
 *   - -1 when failure
 */
ssize_t _aloe_file_size(const void *f, int is_fd);

/**
 *
 * @param fname
 * @param mode ref to fopen
 * @param fmt
 * @param va
 * @return Size of written or -1 when failure
 */
ssize_t aloe_file_vfprintf2(const char *fname, const char *mode,
		const char *fmt, va_list va) __attribute__((format(printf, 3, 0)));
ssize_t aloe_file_fprintf2(const char *fname, const char *mode,
		const char *fmt, ...) __attribute__((format(printf, 3, 4)));

int aloe_file_fread(const char *fname, aloe_buf_t *buf);

int aloe_file_fwrite(const char *fname, aloe_buf_t *buf);

/** Check the error number indicate nonblocking state. */
#define ALOE_ENO_NONBLOCKING(_e) ((_e) == EAGAIN || (_e) == EINPROGRESS)

/** Set nonblocking flag. */
int aloe_file_nonblock(int fd, int en);

#define aloe_sockaddr_family(_sa) ((((struct sockaddr_in*)(_sa))->sin_family == AF_INET) ? AF_INET : \
		(((struct sockaddr_in6*)(_sa))->sin6_family == AF_INET6) ? AF_INET6 : \
		(((struct sockaddr_un*)(_sa))->sun_family == AF_UNIX) ? AF_UNIX : \
		AF_UNSPEC)

int aloe_ip_socket(struct sockaddr*);

/**
 *
 * @param
 * @param cs SOCK_STREAM, SOCK_DGRAM, etc.
 * @param backlog
 * @return
 */
int aloe_ip_bind(struct sockaddr*, int cs);

int aloe_ip_listener(struct sockaddr*, int cs, int backlog);

#define aloe_ip_str_addr 0x1
#define aloe_ip_str_port 0x2
int aloe_ip_str(struct sockaddr *sa, aloe_buf_t *buf, unsigned flag);

#define aloe_ipv6_listener(_p, _bg) aloe_ip_listener(&(struct sockaddr_in6){ \
	.sin6_port = htons(_p), .sin6_family = AF_INET6, .sin6_addr = in6addr_any}, \
	_bg)

#define aloe_ipv4_listener(_p, _bg) aloe_ip_listener((struct sockaddr*)&((struct sockaddr_in){ \
	.sin_port = htons(_p), .sin_family = AF_INET, .sin_addr = {INADDR_ANY}}), \
	_bg)

#define aloe_local_socket_listener(_p, _bg) aloe_ip_listener((struct sockaddr*)&((struct sockaddr_un){ \
	.sun_path = _p, .sin_family = AF_UNIX}), _bg)

int _aloe_file_stdout(const char*, FILE**, int);
#define aloe_file_stdout(_fn) _aloe_file_stdout(_fn, NULL, STDOUT_FILENO)
#define aloe_file_stderr(_fn) _aloe_file_stdout(_fn, NULL, STDERR_FILENO)

int aloe_accessory_name_refine(aloe_buf_t *buf);

/** Convert excluding a-zA-Z0-9 to underscore.
 *
 * @param buf
 * @return How many bytes revised.
 */
int aloe_hostname_refine(aloe_buf_t *buf);

/** Strip whitespace at begin and end. */
int aloe_hostname_refine2(aloe_buf_t *buf);

int aloe_hostname_get(aloe_buf_t *buf);

#define _aloe_hostname_set(_fn, _buf) ( \
		(!(_fn) || aloe_file_fwrite(_fn, _buf) == ((_buf)->lmt - (_buf)->pos)) \
		&& sethostname((char*)(_buf)->data + (_buf)->pos, \
				(_buf)->lmt - (_buf)->pos) == 0)
int aloe_hostname_set(const char *fn_cfg, aloe_buf_t *buf);

__attribute__((format(printf, 2, 3)))
int aloe_hostname_printf(const char *fn_cfg, const char *fmt, ...);

void* aloe_perfev_init(void);
void aloe_perfev_destroy(void*);
long long aloe_perfev_enable(void*, int);

/** @} ALOE_EV_MISC */

/** @addtogroup ALOE_EV_TIME
 * @{
 */

/** Formalize time value. */
#define ALOE_TIMESEC_NORM(_sec, _subsec, _subscale) if ((_subsec) >= _subscale) { \
		(_sec) += (_subsec) / _subscale; \
		(_subsec) %= (_subscale); \
	}

/** Compare 2 time value. */
#define ALOE_TIMESEC_CMP(_a_sec, _a_subsec, _b_sec, _b_subsec) ( \
	((_a_sec) > (_b_sec)) ? 1 : \
	((_a_sec) < (_b_sec)) ? -1 : \
	((_a_subsec) > (_b_subsec)) ? 1 : \
	((_a_subsec) < (_b_subsec)) ? -1 : \
	0)

/** Subtraction for time value. */
#define ALOE_TIMESEC_SUB(_a_sec, _a_subsec, _b_sec, _b_subsec, _c_sec, \
		_c_subsec, _subscale) \
	if ((_a_subsec) < (_b_subsec)) { \
		(_c_sec) = (_a_sec) - (_b_sec) - 1; \
		(_c_subsec) = (_subscale) + (_a_subsec) - (_b_subsec); \
	} else { \
		(_c_sec) = (_a_sec) - (_b_sec); \
		(_c_subsec) = (_a_subsec) - (_b_subsec); \
	}

/** Addition for time value. */
#define ALOE_TIMESEC_ADD(_a_sec, _a_subsec, _b_sec, _b_subsec, _c_sec, \
		_c_subsec, _subscale) do { \
	(_c_sec) = (_a_sec) + (_b_sec); \
	(_c_subsec) = (_a_subsec) + (_b_subsec); \
	ALOE_TIMESEC_NORM(_c_sec, _c_subsec, _subscale); \
} while(0)

#define ALOE_TIMESEC_TD1(_a_sec, _a_subsec, _b_sec, _b_subsec, _subscale) \
		((_a_subsec) < (_b_subsec) ? \
				((_a_sec) - (_b_sec) - 1) * (_subscale) + (_a_subsec) + (_subscale) - (_b_subsec) : \
				((_a_sec) - (_b_sec)) * (_subscale) + (_a_subsec) - (_b_subsec))


/** Normalize timeval.
 *
 * |a|
 *
 * @param a
 * @return (a)
 */
struct timeval* aloe_timeval_norm(struct timeval *a);

/** Compare timeval.
 *
 * |a - b|
 *
 * @param a A normalized timeval
 * @param b A normalized timeval
 * @return 1, -1 or 0 if (a) later/early/equal then/to (b)
 */
int aloe_timeval_cmp(const struct timeval *a, const struct timeval *b);

/** Subtraction timeval.
 *
 * c = a - b
 *
 * @param a A normalized timeval, must later then (b)
 * @param b A normalized timeval, must early then (a)
 * @param c Hold result if not NULL
 * @return (c)
 */
struct timeval* aloe_timeval_sub(const struct timeval *a, const struct timeval *b,
		struct timeval *c);

/** Addition timeval.
 *
 * c = a + b
 *
 * @param a
 * @param b
 * @param c
 * @return
 */
struct timeval* aloe_timeval_add(const struct timeval *a, const struct timeval *b,
		struct timeval *c);

/** @} ALOE_EV_TIME */

#ifdef __cplusplus
} // extern "C"
#endif


#endif /* PACKAGE_ADMIN_ADMIN_H_ */
