/**
 * SPDX-License-Identifier: MIT
 *
 * @file	momicalc.c
 * @brief	Per cpu usage calculate command.
 * 
 * Copyright (c) 2023 Automotive Grade Linux Instrument Cluster Expert Group
 *
 * This source code is based on https://github.com/ohmae/cpu-usage.
 * That was developed by OHMAE Ryosuke.
 * That software is released under the MIT License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#define LINE_BUFFER_SIZE (8192)
/**
 * @struct	s_stat_cputime
 * @brief	The structure for save to par cpu usage information from /proc/stat.
 */
typedef struct s_stat_cputime {
	uint64_t user;       /**< Time spent in user mode. */
	uint64_t nice;       /**< Time spent in user mode with low priority (nice). */
	uint64_t system;     /**< Time spent in system mode. */
	uint64_t idle;       /**< Time spent in the idle task. */
	uint64_t iowait;     /**< Time waiting for I/O to complete. */
	uint64_t irq;        /**< Time servicing interrupts. */
	uint64_t softirq;    /**< Time servicing softirqs. */
	uint64_t steal;      /**< Stolen time, which is the time spent in other operating systems when running in a virtualized environment. */
	uint64_t guest;      /**< Time spent running a virtual CPU for guest operating systems under the control of the Linux kernel. */
	uint64_t guest_nice; /**< Time spent running a niced guest.  */
} stat_cputime_t;


#define CORE_NUM_MAX (64)

/**
 * @struct	s_stat_cputimes
 * @brief	The structure for save to cpu usage information from /proc/stat.
 */
typedef struct s_stat_cputimes {
	stat_cputime_t total;
	stat_cputime_t cpus[CORE_NUM_MAX];
	unsigned int core_num;
} stat_cputimes_t;

/**
 * @struct	s_cpus_usage
 * @brief	The structure for save to cpu usage information from /proc/stat.
 */
typedef struct s_cpus_usage {
	double total;
	double cpus[CORE_NUM_MAX];
	unsigned int core_num;
} cpus_usage_t;

static int set_cpu_info_value(stat_cputime_t *pcputime, int number, uint64_t value)
{
	switch (number) {
	case 0 :
		pcputime->user = value;
		break;

	case 1 :
		pcputime->nice = value;
		break;

	case 2 :
		pcputime->system = value;
		break;

	case 3 :
		pcputime->idle = value;
		break;

	case 4 :
		pcputime->iowait = value;
		break;

	case 5 :
		pcputime->irq = value;
		break;

	case 6 :
		pcputime->softirq = value;
		break;

	case 7 :
		pcputime->steal = value;
		break;

	case 8 :
		pcputime->guest = value;
		break;

	case 9 :
		pcputime->guest_nice = value;
		break;
	default:
		; //nop
	}

	return 0;
}
/**
 * @brief Load cpu information from file.
 *
 * @param[out] pcputimes The stroage for cpu information.
 * @return
 */
static int load_last_cpu_info(stat_cputimes_t *pcputimes)
{
	int result = -1;
	size_t read_count = 0;
	FILE *fp = NULL;

	fp = fopen("/tmp/get-cpu-usage-last.bin", "rb");
	if (fp == NULL) {
		result = -1;
		goto error_return;
	}

	read_count = fread(pcputimes, sizeof(stat_cputimes_t), 1, fp);
	fclose(fp);

	if (read_count == 1) {
		result = 0;
	}

error_return:
	return result;
}

/**
 * @brief Store cpu information to file.
 *
 * @param[out] pcputimes The stroage for cpu information.
 * @return
 */
static int store_latest_cpu_info(const stat_cputimes_t *pcputimes)
{
	int result = -1;
	size_t read_count = 0;
	FILE *fp = NULL;

	fp = fopen("/tmp/get-cpu-usage-last.bin", "wb");
	if (fp == NULL) {
		result = -1;
		goto error_return;
	}

	read_count = fwrite(pcputimes, sizeof(stat_cputimes_t), 1, fp);
	fclose(fp);

	if (read_count == 1) {
		result = 0;
	}
	
error_return:
	return result;
}
/**
 * @brief Get cpu information from /proc/stat.
 *
 * @param[out] pcputimes The stroage for cpu information.
 * @return
 */
static int get_cpu_info_from_stat(stat_cputimes_t *pcputimes)
{
	int ret = -1, result = 0;
	int cpu_count = 0;
	FILE *fp = NULL;
	char line_buffer[LINE_BUFFER_SIZE];


	fp = fopen("/proc/stat", "r");
	if (fp == NULL) {
		result = -1;
		goto error_return;
	}

	pcputimes->core_num = 0;
	
	do {
		char *pgs = NULL;
		line_buffer[0] = '\0';

		pgs = fgets(line_buffer, sizeof(line_buffer), fp);
		if (pgs == NULL) {
			if (feof(fp) != 0) {
				break;
			}
			goto error_return;
		}

		ret = strncmp("cpu", line_buffer, 3);
		if (ret == 0) {
			// Got a cpu informatin line.
			int token_counter = 0;
			stat_cputime_t *pelem = NULL;
			char *ptok = NULL, *pstr = line_buffer, *psave = NULL;

			do {
				ptok = strtok_r(pstr, " ", &psave);
				if (ptok == NULL) {
					break;
				}

				if (pstr != NULL) {
					// 1st token
					ret = strcmp("cpu", ptok);
					if (ret == 0) {
						pelem = &pcputimes->total;
					} else {
						ret = strlen(ptok);
						if (ret > 3) {
							long ltemp = 0;

							errno = 0;
							ltemp = strtol(&ptok[3], NULL, 10);
							if ((ltemp != LONG_MAX) && (ltemp < CORE_NUM_MAX) && (ltemp >= 0)) {
								cpu_count = (int)ltemp;
								pelem = &pcputimes->cpus[cpu_count];
								pcputimes->core_num++;
							} else {
								//error data
								break;
							}
						}
					}

					pstr = NULL;
				} else {
					// Not a 1st token
					unsigned long long ulltemp = 0;
					uint64_t valute_u64 = 0;

					errno = 0;
					ulltemp = strtoull(ptok, NULL, 10);
					if (ulltemp != ULLONG_MAX) {
						valute_u64 = (uint64_t)ulltemp;
					}

					(void) set_cpu_info_value(pelem, token_counter, valute_u64);
					token_counter++;
				}
			} while(1);
		}
	} while(1);

error_return:
	if (fp != NULL) {
		fclose(fp);
	}

	return result;
}
/**
 * @brief Get cpu information from /proc/stat.
 *
 * @param[out] pcputimes The stroage for cpu information.
 * @return
 */
static int get_cpu_time_delta(stat_cputime_t *dest, const stat_cputime_t *latest, const stat_cputime_t *last)
{
	dest->user = latest->user - last->user;
	dest->nice = latest->nice - last->nice;
	dest->system = latest->system - last->system;
	dest->idle = latest->idle - last->idle;
	dest->iowait = latest->iowait - last->iowait;
	dest->irq = latest->irq - last->irq;
	dest->softirq = latest->softirq - last->softirq;
	dest->steal = latest->steal - last->steal;
	dest->guest = latest->guest - last->guest;
	dest->guest_nice = latest->guest_nice - last->guest_nice;

	return 0;
}
/**
 * @brief Get cpu information from /proc/stat.
 *
 * @param[out] pcputimes The stroage for cpu information.
 * @return
 */
static int get_cpus_time_delta(stat_cputimes_t *dest, const stat_cputimes_t *latest, const stat_cputimes_t *last)
{
	if (latest->core_num >= CORE_NUM_MAX) {
		return -1;
	}

	(void)get_cpu_time_delta(&dest->total, &latest->total, &last->total);

	for(unsigned int i=0; i < latest->core_num; i++) {
		get_cpu_time_delta(&dest->cpus[i], &latest->cpus[i], &last->cpus[i]);
	}

	dest->core_num = latest->core_num;

	return 0;
}
/**
 * @brief Calculate the denominator.
 *
 * @param[in] time stat_cputime_t
 * @return
 */
static uint64_t calc_denominator(const stat_cputime_t *time)
{
	return time->user + time->nice + time->system
			+ time->idle + time->iowait + time->irq + time->softirq
			+ time->steal + time->guest + time->guest_nice;
}
/**
 * @brief Calculate the cpu runtime.
 *
 * @param[in] time stat_cputime_t
 * @return
 */
static uint64_t calc_runtime(const stat_cputime_t *time)
{
	return time->user + time->nice + time->system
			+ time->irq + time->softirq
			+ time->steal + time->guest + time->guest_nice;
}
/**
 * @brief Calc cpu usage from stat_cputime_t.
 *
 * @param[out] pcputimes The stroage for cpu information.
 * @return
 */
static double calc_cpu_usage(const stat_cputime_t *measurement)
{
	uint64_t denominator = calc_denominator(measurement);
	uint64_t runtime = calc_runtime(measurement);
	double result = 0.0;

	if (denominator != 0) {
		result = ((double)runtime) / ((double)denominator);
	}

	return result;
}
/**
 * @brief Get cpu information from /proc/stat.
 *
 * @param[out] pcputimes The stroage for cpu information.
 * @return
 */
static int get_cpus_usage(cpus_usage_t *usage, stat_cputimes_t *measurement)
{
	if (measurement->core_num >= CORE_NUM_MAX) {
		return -1;
	}

	usage->core_num = measurement->core_num;

	usage->total = calc_cpu_usage(&measurement->total);

	for(unsigned int i=0; i < measurement->core_num; i++) {
		usage->cpus[i] = calc_cpu_usage(&measurement->cpus[i]);
	}

	return 0;
}
/**
 * @brief The main function for get cpu usage.
 */
int main(int argc, char **argv)
{
	int ret = -1;
	int num = sysconf(_SC_NPROCESSORS_ONLN);
	stat_cputimes_t info[3];
	cpus_usage_t usage;

	(void) memset(&info[0], 0, sizeof(info[0]));
	(void) memset(&info[1], 0, sizeof(info[1]));
	(void) memset(&info[2], 0, sizeof(info[2]));
	(void) memset(&usage, 0, sizeof(usage));

	ret = get_cpu_info_from_stat(&info[0]);
	if (ret == 0){
		ret = load_last_cpu_info(&info[1]);
		if (ret != 0) {
			(void) memset(&info[1], 0, sizeof(info[1]));
		}

		(void)get_cpus_time_delta(&info[2], &info[0], &info[1]);

		(void)store_latest_cpu_info(&info[0]);

		ret = get_cpus_usage(&usage, &info[2]);
		if (ret == 0) {
			// out json format
			fprintf(stdout, "{\n");
			fprintf(stdout, "\t\"cpuusage\": {\n");
			for(int i=0; i < num;i++) {
				fprintf(stdout, "\t\t\"%d\": %2.2lf", i, usage.cpus[i]*100);
				if (i != (num-1)) {
					fprintf(stdout, ",\n");
				} else {
					fprintf(stdout, "\n");
				}
			}
			fprintf(stdout, "\t}\n");
			fprintf(stdout, "}\n");
		}
	}

	return 0;
}
