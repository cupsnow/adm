/**
 * @author joelai
 */

#ifndef _H_ALOE_AIR192
#define _H_ALOE_AIR192

#include "admin.h"
#include <regex.h>
#include <cjson/cJSON.h>

/** @defgroup ALOE_AIR192_API Air192 API
 * @brief Air192 API.
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup ALOE_AIR192_API
 * @{
 */

#define persist_cfg "/media/cfg"
#define accname_cfg persist_cfg "/acc_name"
#define hostname_cfg persist_cfg "/hostname"
#define wpasup_cfg persist_cfg "/wpa_supplicant.conf"
#define eth_cfg persist_cfg "/eth.conf"
#define wlan_cfg persist_cfg "/wlan.conf"
#define macaddr_cfg persist_cfg "/macaddr.conf"
#define spkcal_cfg persist_cfg "/spklatency"
#define wol_cfg persist_cfg "/wol.conf"
#define snhash_cfg persist_cfg "/snhash.conf"
#define spkcal_raw "/var/run/spklatency"
#define led_cfg "/etc/led.conf"
#define oob_cfg "/etc/outofbox"
#define promisc_cfg "/etc/promisc"
#define resolv_cfg "/var/run/udhcpc/resolv.conf"
#define wfa_cfg "/etc/wfa.conf"

int air192_name_get(const char **fns, aloe_buf_t *buf,
		int (*refine)(aloe_buf_t*));

cJSON* air192_cfg_load(const char **fns, aloe_buf_t *buf);

int air192_cfg_load2(const char **fns, aloe_buf_t *buf, int max);

uint16_t air192_eve_hash4(const void *data, size_t sz);

int air192_GetSerialNumberHashString(const char *inSerialNumber,
		char *outHashStrBuf, int outHashStrBufSize);

/**
 *
 * @param fname
 * @param fmt
 * @return
 *   - 0 for file not exist or size zero
 *   - negative for error
 *   - otherwise number of scanf
 */
__attribute__((format(scanf, 2, 3)))
int air192_file_scanf1(const char *fname, const char *fmt, ...);

int air192_regex_test1(const char *fmt, const char *pat, int cflags,
		size_t nmatch, regmatch_t *pmatch);

__attribute__((format(printf, 3, 4)))
int air192_led_set(int led_val, unsigned long send_dur,
		const char *name_fmt, ...);

int air192_adk_paired(const char **fns);

#define air192_d2(_fmt, _args...) do { \
	fprintf(stdout, "[air192][%s][#%d]" _fmt, __func__, __LINE__, ##_args); \
	fflush(stdout); \
} while(0)


typedef struct air192_cgireq_rec {
	const char *reason;
	int prog_st, prog_iter, err;
	aloe_buf_t cmdbuf;
	cJSON *jroot, *jout;
} air192_cgireq_t;

enum {
	air192_cgireq_prog_null = 0,
	air192_cgireq_prog_complete = air192_cgireq_prog_null + 100,
	air192_cgireq_prog_failed,
	air192_cgireq_prog_fatal, // including less then prog_null
	air192_cgireq_prog_refine_rc, // unlock cgi request
	air192_cgireq_prog_max,
};

#define air192_cgireq_reason(_req, ...) if ((_req)->cmdbuf.data) { \
	aloe_buf_clear(&(_req)->cmdbuf); \
	if (aloe_buf_printf(&(_req)->cmdbuf, __VA_ARGS__) < 0) { \
		aloe_buf_printf(&(_req)->cmdbuf, "%s #%d %s", __func__, __LINE__, "Failed compose reason"); \
	} \
	(_req)->reason = (char*)(_req)->cmdbuf.data; \
	log_d("%s\n", (_req)->reason); \
}

__attribute__((format(printf, 3, 4)))
int air192_cgireq_open(air192_cgireq_t *req, const char *prog_lock,
		const char *fmt, ...);

int air192_cgireq_ipcfg_read(const char *cfg, cJSON **jout, aloe_buf_t *reason);
int air192_cgireq_ipcfg_save(const char *ip, const char *msk, const char *gw,
		const char *dns, aloe_buf_t *reason, const char *cfg);
int air192_cgireq_ipcfg_unmarshal(cJSON *jroot, const char **ip,
		const char **msk, const char **gw, const char **dns,
		aloe_buf_t *reason);

__attribute__((format(printf, 4, 5)))
int air192_sus_set(int whence, int delay, unsigned long send_dur,
		const char *name_fmt, ...);

typedef int (*air192_cli_cb_t)(void *cbarg, int len, const char *msg);
void* air192_cli_start(const char *name, air192_cli_cb_t cb, void *cbarg);
void air192_cli_stop(void*);

__attribute__((format(printf, 3, 0)))
int air192_cli_vsend(const char *name, unsigned long send_dur,
		const char *fmt, va_list va);
__attribute__((format(printf, 3, 4)))
int air192_cli_send(const char *name, unsigned long send_dur,
		const char *fmt, ...);

/** @} ALOE_AIR192_API */

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* _H_ALOE_AIR192 */
