/*
 * @auther joelai
 */

#include "priv.h"

#define TEST_AIR192 1

#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/times.h>
#include <syslog.h>
#include <sys/random.h>
#include <admin/unitest.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <pthread.h>

#if defined(TEST_AIR192) && TEST_AIR192
#include <admin/air192.h>
#endif

#include <cjson/cJSON.h>

static aloe_test_flag_t test1_macro1(aloe_test_case_t *test_case) {
#define M1
#define M1_0 0
#define M1_1 1

#if _M1
	log_d("#if _M1\n");
#else
	// here
	log_d("#if _M1 #else\n");
#endif

// Compile error: #if with no expression
//#if M1
//	log_d("#if M1\n");
//#else
//	log_d("#if M1 #else\n");
//#endif

#if M1_0
	log_d("#if M1_0\n");
#else
	// here
	log_d("#if M1_0 #else\n");
#endif

#if M1_1
	// here
	log_d("#if M1_1\n");
#else
	log_d("#if M1_1 #else\n");
#endif
	return aloe_test_flag_result_pass;
}

static int accname1_refine1(aloe_buf_t *buf) {
	return aloe_accessory_name_refine(buf);
}

static int accname1_refine2(aloe_buf_t *buf) {
	if (accname1_refine1(buf) != 0) return -1;
	if (aloe_hostname_refine(buf) != 0) return -1;
	return 0;
}

static aloe_test_flag_t test1_accname1(aloe_test_case_t *test_case) {
	aloe_buf_t buf = {0};
	int r;

	ALOE_TEST_ASSERT_THEN(aloe_buf_aprintf(&buf, 255, " ac na-m ") > 0
			&& buf.pos == 9,
			test_case, failed, {
		log_e("buf[pos=%d, lmt=%d]\n", buf.pos, buf.lmt);
		goto finally;
	});

	ALOE_TEST_ASSERT_THEN(aloe_accessory_name_refine(aloe_buf_flip(&buf)) == 0
			&& buf.pos == 1 && buf.lmt == 8,
			test_case, failed, {
		log_e("buf[pos=%d, lmt=%d]\n", buf.pos, buf.lmt);
		goto finally;
	});

	aloe_hostname_refine(&buf);
	ALOE_TEST_ASSERT_THEN(strcmp((char*)buf.data + buf.pos, "ac_na_m") == 0,
			test_case, failed, {
		log_e("buf[pos=%d, lmt=%d], buf[buf.pos]: %s\n", buf.pos,
				buf.lmt, (char*)buf.data + buf.pos);
		goto finally;
	});

	{
		air192_name_get(NULL, aloe_buf_clear(&buf), &accname1_refine1);
		aloe_buf_flip(&buf);
		log_d("acc name: %s\n", (char*)buf.data + buf.pos);
		air192_name_get(NULL, aloe_buf_clear(&buf), &accname1_refine2);
		aloe_buf_flip(&buf);
		log_d("acc -> hostname: %s\n", (char*)buf.data + buf.pos);
	}

	{
		char hash_str[5], tro[] = "a;sdccfv20";
		uint16_t hash = air192_eve_hash4(tro, strlen(tro));

		air192_GetSerialNumberHashString(tro, hash_str, sizeof(hash_str));
		log_d("hash: 0x%x, str: %s\n", hash, hash_str);
	}

	{
	    // Generate Wi-Fi identifier.
	    uint8_t wiFiIdentifier[6], wiFiIdentifierStr[sizeof(wiFiIdentifier) * 2 + 4];
	    int i;

	    i = 0;
	    while (i < (int)sizeof(wiFiIdentifier)) {
	    	ALOE_TEST_ASSERT_THEN(r = getrandom(wiFiIdentifier + i,
	    			sizeof(wiFiIdentifier) - i, 0) >= 0,
	    			test_case, failed_suite, {
	    		r = errno;
	    		log_e("getrandom: %s\n", strerror(r));
	    		goto finally;
	    	});
	    	i += r;
	    }
	    for (i = 0; i < (int)sizeof(wiFiIdentifier); i++) {
	    	snprintf((char*)wiFiIdentifierStr + i * 2, 3, "%02X", wiFiIdentifier[i]);
	    }
	    wiFiIdentifierStr[sizeof(wiFiIdentifier) * 2] = '\0';

		char apName[80];
	    aloe_buf_t apNameFb = {.data = apName, .cap = sizeof(apName)};

	    if (air192_name_get(NULL, aloe_buf_clear(&apNameFb),
	    		&aloe_accessory_name_refine) != 0 || apNameFb.pos <= 0) {
	    	apNameFb.pos = snprintf(apName, sizeof(apName), "%s", "Air192");
	    }
	    log_d("apName: %s, len: %d\n", apName, (int)apNameFb.pos);

	    // name-hexStr
	    ALOE_TEST_ASSERT_THEN((apNameFb.lmt - apNameFb.pos >= 6)
	    		&& air192_GetSerialNumberHashString((char*)wiFiIdentifierStr,
	    				(char*)apNameFb.data + apNameFb.pos + 1, 5) == 0,
		    			test_case, failed_suite, {
			goto finally;
		});
	    ((char*)apNameFb.data)[apNameFb.pos] = '-';
	    apNameFb.pos += 5;
	    log_d("apName: %s, len: %d\n", apName, (int)apNameFb.pos);
	}

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (buf.data) free(buf.data);
	return test_case->flag_result;
}

static aloe_test_flag_t test1_cjson1(aloe_test_case_t *test_case) {
	aloe_buf_t buf = {0};
	cJSON *jroot = NULL;
	const char *str, *fns[] = {
#define TEST1_CJSON1_CFG1 "test1_cjson1.json"
			TEST1_CJSON1_CFG1,
			NULL
	};

	ALOE_TEST_ASSERT_THEN(aloe_buf_aprintf(aloe_buf_clear(&buf), -1,
			"{"
				"\"name\": \"%s\","
				"\"num\": %d"
			"}", "bob", 8) > 0
			&& aloe_file_fwrite(TEST1_CJSON1_CFG1, aloe_buf_flip(&buf)) > 0,
			test_case, failed, {
		goto finally;
	});

	ALOE_TEST_ASSERT_THEN((jroot = air192_cfg_load(fns, &buf))
			&& (str = cJSON_GetStringValue(cJSON_GetObjectItem(jroot, "name")))
			&& strcmp(str, "bob") == 0,
			test_case, failed, {
		goto finally;
	});
	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (jroot) cJSON_Delete(jroot);
	if (buf.data) free(buf.data);
	return test_case->flag_result;
}

typedef enum perf_ev_paranoia_lvl_enum {
	/*
    * perf event paranoia level:
    *  -1 - not paranoid at all
    *   0 - disallow raw tracepoint access for unpriv
    *   1 - disallow cpu events for unpriv
    *   2 - disallow kernel profiling for unpriv
    */
	perf_ev_paranoia_lvl_na = -1,
	perf_ev_paranoia_lvl_priv_raw = 0,
	perf_ev_paranoia_lvl_priv_cpu = 1,
	perf_ev_paranoia_lvl_priv_kern = 2
} perf_ev_paranoia_lvl_t;

#define perf_ev_paranoia_str(_p) ( \
	((_p) == perf_ev_paranoia_lvl_na) ? "not paranoid at all" : \
    ((_p) == perf_ev_paranoia_lvl_priv_raw) ? "disallow raw tracepoint access for unpriv" : \
	((_p) == perf_ev_paranoia_lvl_priv_cpu) ? "disallow cpu events for unpriv" : \
	((_p) == perf_ev_paranoia_lvl_priv_kern) ? "disallow kernel profiling for unpriv" : \
	"unknown")

#define PERF_EV_PARANOIA_FN "/proc/sys/kernel/perf_event_paranoid"

static int pref_paranoia(int *lvl) {
    int fd = -1, r, paranoia_lvl;
    char buf[32];

    if ((r = aloe_file_size(PERF_EV_PARANOIA_FN, 0)) < 0) {
		r = ENOENT;
		log_d("Not support perf_event (miss %s)\n", PERF_EV_PARANOIA_FN);
		goto finally;
    }

    if ((fd = open(PERF_EV_PARANOIA_FN, O_RDONLY, 0444)) == -1) {
		r = errno;
		log_e("open %s, %s\n", PERF_EV_PARANOIA_FN, strerror(r));
		goto finally;
    }

    if (aloe_file_nonblock(fd, 1) != 0) {
		r = errno;
		log_e("nonblock %s, %s\n", PERF_EV_PARANOIA_FN, strerror(r));
		goto finally;
    }

    r = read(fd, buf, sizeof(buf));
    if (r == 0) {
		r = EIO;
		log_e("read %s, closed\n", PERF_EV_PARANOIA_FN);
		goto finally;
    }
    if (r < 0) {
    	r = errno;
		log_e("read %s, %s\n", PERF_EV_PARANOIA_FN, strerror(r));
		goto finally;
    }
    if (r >= (int)sizeof(buf)) {
		r = EIO;
		log_e("read %s, insufficient buffer\n", PERF_EV_PARANOIA_FN);
		goto finally;
    }

    buf[r] = '\0';
	paranoia_lvl = strtol(buf, NULL, 0);
	log_d("perf_event_paranoid: %d (%s)\n", paranoia_lvl,
			perf_ev_paranoia_str(paranoia_lvl));

	if (lvl) *lvl = paranoia_lvl;
	r = 0;
finally:
	if (fd != -1) close(fd);
	return r;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags) {
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
	return ret;
}

static
__attribute__((unused))
aloe_test_flag_t test1_perf1(aloe_test_case_t *test_case) {
	struct perf_event_attr pe;
	long long count;
	int fd = -1, sz, r;

	ALOE_TEST_ASSERT_THEN(pref_paranoia(NULL) == 0, test_case, failed_suite,
			{ log_e("perf_event: not support\n"); goto finally; });

	memset(&pe, 0, sizeof(pe));
	pe.type = PERF_TYPE_HARDWARE;
	pe.size = sizeof(pe);
	pe.config = PERF_COUNT_HW_CPU_CYCLES;
	pe.disabled = 1;
	pe.exclude_kernel = 1;
	pe.exclude_hv = 1;

	ALOE_TEST_ASSERT_THEN((fd = perf_event_open(&pe, 0, -1, -1,
			PERF_FLAG_FD_NO_GROUP)) != -1,
			test_case, failed, {
		r = errno;
		log_e("open perf_event: %s\n", strerror(r));
		goto finally;
	});

	ioctl(fd, PERF_EVENT_IOC_RESET, 0);
	ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

	printf("Measuring CPU cycles for this printf\n");

	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	read(fd, &count, sizeof(count));

	printf("Measured %lld\n", count);

	sz = 3;
	for (int i = 0; i < sz; i++) {
		ioctl(fd, PERF_EVENT_IOC_RESET, 0);
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
		sleep(1);
		ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
		read(fd, &count, sizeof(count));
		printf("pref_events (%d/%d) sleep(1): %lld\n", i + 1, sz, count);
	}
	close(fd);
	fd = -1;

	log_d("CLOCKS_PER_SEC: %ld\n", (long)CLOCKS_PER_SEC);

	sz = 3;
	for (int i = 0; i < sz; i++) {
		clock_t ts0 = clock();

		sleep(1);
		clock_t ts1 = clock();
		printf("clock (%d/%d) sleep(1): %lld\n", i + 1, sz,
				(long long)(ts1 - ts0));
	}

	sz = 3;
	for (int i = 0; i < sz; i++) {
		clock_t ts0 = times(NULL);

		sleep(1);
		clock_t ts1 = times(NULL);
		printf("times (%d/%d) sleep(1): %lld\n", i + 1, sz,
				(long long)(ts1 - ts0));
	}
	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	if (fd != -1) close(fd);
	return test_case->flag_result;
}

static
__attribute__((unused))
aloe_test_flag_t test1_perf2(aloe_test_case_t *test_case) {
	struct {
		void *ctx;
		long long count;
	} perfev[2] = {0};
	int sz;

#define perfev_foreach() for (int i = 0; i < (int)aloe_arraysize(perfev); i++)
#define perfev_close() perfev_foreach() { \
	if (perfev[i].ctx) { \
		aloe_perfev_destroy(perfev[i].ctx); \
		perfev[i].ctx = NULL; \
	} \
}

	ALOE_TEST_ASSERT_THEN((perfev[0].ctx = aloe_perfev_init()),
			test_case, failed, {
		goto finally;
	});

	sz = 3;
	for (int i = 0; i < sz; i++) {
		aloe_perfev_enable(perfev[0].ctx, 1);
		sleep(1);
		perfev[0].count = aloe_perfev_enable(perfev[0].ctx, 0);
		printf("aloe_perfev[0] (%d/%d) sleep(1): %lld\n", i + 1, sz,
				perfev[0].count);
	}

	perfev_close();

	test_case->flag_result = aloe_test_flag_result_pass;
finally:
	perfev_close();
	return test_case->flag_result;
}

static aloe_test_flag_t test1_ledconf1(aloe_test_case_t *test_case) {
	char pat[] = {
		"led_power 38\n"
		"led_standby 39\n"
		"  # led_gear 122\n"
		"led_gear 123\n"
		"\n"
		"sw_gear 144\n"
	};
	aloe_buf_t buf = {.data = pat, .cap = sizeof(pat)};
	char *pl, *pl_tok;
	int led_ex = 0;

	buf.pos = strlen((char*)buf.data);
	aloe_buf_flip(&buf);

	for (pl = strtok_r((char*)buf.data + buf.pos, "\r\n", &pl_tok);
			pl; pl = strtok_r(NULL, "\r\n", &pl_tok)) {
		char *name, *val_str, *plk_tok;
		long gpio_num;

		pl += strspn(pl, aloe_str_sep);
		if (strncasecmp(pl, "led_", 4) != 0
				|| (!isalpha(pl[4]) && isdigit(pl[4]))) {
			log_d("Ignore line: %s\n", pl);
			continue;
		}

		if (!(name = strtok_r(pl + 4, aloe_str_sep, &plk_tok))
				|| !(val_str = strtok_r(NULL, aloe_str_sep, &plk_tok))) {
			continue;
		}
		if (aloe_strtol(val_str, NULL, 0, &gpio_num) != 0) {
			log_e("Parse led %s, gpio #%s\n", name, val_str);
			continue;
		}

		if (strcasecmp(name, "power") == 0) {
			log_d("led %s, gpio #%d\n", name, gpio_num);
			continue;
		}

		if (strcasecmp(name, "standby") == 0) {
			log_d("led %s, gpio #%d\n", name, gpio_num);
			continue;
		}
		log_d("led[%d] %s, gpio #%d\n", led_ex++, name, gpio_num);
	}

	test_case->flag_result = aloe_test_flag_result_pass;
finally: __attribute__((unused));
	return test_case->flag_result;
}

typedef struct {
	void *ctx;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int argc;
	char args[200], *argv[20];
} test1_mqcli1_t;

static const char mqcli_prename[] = air192_mqcli_name_prefix;
#define mqcli_prename_sz (sizeof(mqcli_prename) - 1)

#define HAPLogError(_ignore1, ...) log_e(__VA_ARGS__)
static int test1_mqcli1_cli(void *cbarg, int len, const char *msg) {
	test1_mqcli1_t *mqcli = (test1_mqcli1_t*)cbarg;
	int r, i;

	air192_d2("recv %d bytes, %s\n", len, msg);
	if (len >= (int)sizeof(mqcli->args)) {
		r = EIO;
        HAPLogError(&kHAPLog_Default, "Too long args\n");
        goto finally;
	}
	memcpy(mqcli->args, msg, len);
	mqcli->args[len] = '\0';
	mqcli->argc = aloe_arraysize(mqcli->argv);
	if ((r = aloe_cli_tok(mqcli->args, &mqcli->argc, mqcli->argv, NULL)) != 0
			|| mqcli->argc >= (int)aloe_arraysize(mqcli->argv)) {
		r = EIO;
		HAPLogError(&kHAPLog_Default, "Too long args\n");
		goto finally;
	}

#if 1
	for (i = 0; i < mqcli->argc; i++) {
		air192_d2("argv[%d/%d]: %s\n", i + 1, mqcli->argc, mqcli->argv[i]);
	}
#endif
	if ((r = pthread_mutex_lock(&mqcli->mutex)) != 0) {
		r = errno;
		log_e("lock mutex: %s\n", strerror(r));
		goto finally;
	}

	if ((r = pthread_cond_broadcast(&mqcli->cond))) {
		r = errno;
		log_e("cond broadcast: %s\n", strerror(r));
		goto finally;
	}

	if ((r = pthread_mutex_unlock(&mqcli->mutex)) != 0) {
		r = errno;
		log_e("unlock mutex: %s\n", strerror(r));
		goto finally;
	}
	r = 0;
finally:
	return r;
}

static aloe_test_flag_t test1_mqcli1(aloe_test_case_t *test_case) {
	test1_mqcli1_t mqcli = {.ctx = NULL};
	struct {
		unsigned mux : 1;
		unsigned cond : 1;
	} init_iter = {0};
	int r;

	ALOE_TEST_ASSERT_THEN((mqcli_prename_sz == strlen(air192_mqcli_name_prefix)),
			test_case, failed, {
		goto finally;
	});

	ALOE_TEST_ASSERT_THEN((r = pthread_mutex_init(&mqcli.mutex, NULL)) == 0,
			test_case, failed, {
		r = errno;
		log_e("alloc mutex: %s\n", strerror(r));
		goto finally;
	});
	init_iter.mux = 1;

	ALOE_TEST_ASSERT_THEN((r = pthread_cond_init(&mqcli.cond, NULL)) == 0,
			test_case, failed, {
		r = errno;
		log_e("alloc cond: %s\n", strerror(r));
		goto finally;
	});
	init_iter.cond = 1;

	ALOE_TEST_ASSERT_THEN((mqcli.ctx = air192_cli_start("test1_mqcli1",
			&test1_mqcli1_cli, &mqcli)), test_case, failed, {
		goto finally;
	});

#define mqcli1_wait() \
	ALOE_TEST_ASSERT_THEN((r = pthread_mutex_lock(&mqcli.mutex)) == 0, \
			test_case, failed, { \
		r = errno; \
		log_e("lock mutex: %s\n", strerror(r)); \
		goto finally; \
	}); \
	ALOE_TEST_ASSERT_THEN((r = pthread_cond_wait(&mqcli.cond, &mqcli.mutex)) == 0, \
			test_case, failed, { \
		r = errno; \
		log_e("cond wait: %s\n", strerror(r)); \
		goto finally; \
	}); \
	ALOE_TEST_ASSERT_THEN((r = pthread_mutex_unlock(&mqcli.mutex)) == 0, \
			test_case, failed, { \
		r = errno; \
		log_e("unlock mutex: %s\n", strerror(r)); \
		goto finally; \
	});

	ALOE_TEST_ASSERT_THEN((air192_cli_send("test1_mqcli1",
			ALOE_EV_INFINITE, "volume 20")) == 0, test_case, failed, {
		goto finally;
	});
	mqcli1_wait();

#if 0
	ALOE_TEST_ASSERT_THEN((air192_cli_send("test1_mqcli1",
			ALOE_EV_INFINITE, "%s", "bye")) == 0, test_case, failed, {
		goto finally;
	});
	mqcli1_wait();
#endif

	test_case->flag_result = aloe_test_flag_result_pass;
finally: __attribute__((unused));
	if (mqcli.ctx) air192_cli_stop(mqcli.ctx);
	if (init_iter.mux) pthread_mutex_destroy(&mqcli.mutex);
	if (init_iter.cond) pthread_cond_destroy(&mqcli.cond);
	return test_case->flag_result;
}

static int test_reporter(unsigned lvl, const char *tag, long lno,
		const char *fmt, ...) {
	va_list va;

	printf("%s #%d ", tag, (int)lno);
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
	return 0;
}

int main(int argc, char **argv) {
	aloe_test_t test_base;
	aloe_test_report_t test_report;

	for (int i = 0; i < argc; i++) {
		log_d("argv[%d/%d]: %s\n", i + 1, argc, argv[i]);
	}

	ALOE_TEST_INIT(&test_base, "Test1");
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/macro1", &test1_macro1);
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/accname1", &test1_accname1);
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/cjson1", &test1_cjson1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/perf1", &test1_perf1);
//	ALOE_TEST_CASE_INIT4(&test_base, "Test1/perf2", &test1_perf2);
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/ledconf1", &test1_ledconf1);
	ALOE_TEST_CASE_INIT4(&test_base, "Test1/mqcli1", &test1_mqcli1);

	ALOE_TEST_RUN(&test_base);

	memset(&test_report, 0, sizeof(test_report));
	test_report.log = &test_reporter;
	aloe_test_report(&test_base, &test_report);

	printf("Report result %s, test suite[%s]"
			"\n  Summary total cases PASS: %d, FAILED: %d(PREREQUISITE: %d), TOTAL: %d\n",
			ALOE_TEST_RESULT_STR(test_base.runner.flag_result, "UNKNOWN"),
			test_base.runner.name,
			test_report.pass, test_report.failed,
			test_report.failed_prereq, test_report.total);

	return 0;
}
