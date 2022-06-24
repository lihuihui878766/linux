// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implementation of get_cpuid().
 *
 * Author: Nikita Shubin <n.shubin@yadro.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <api/fs/fs.h>
#include <errno.h>
#include "../../util/debug.h"
#include "../../util/header.h"

#define CPUINFO_MVEN	"mvendorid"
#define CPUINFO_MARCH	"marchid"
#define CPUINFO_MIMP	"mimpid"
#define CPUINFO		"/proc/cpuinfo"

static char *_get_field(const char *line)
{
	char *line2, *nl;

	line2 = strrchr(line, ' ');
	if (!line2)
		return NULL;

	line2++;
	nl = strrchr(line, '\n');
	if (!nl)
		return NULL;

	return strndup(line2, nl - line2);
}

static char *_get_cpuid(void)
{
	char *line = NULL;
	char *mvendorid = NULL;
	char *marchid = NULL;
	char *mimpid = NULL;
	char *cpuid = NULL;
	int read;
	unsigned long line_sz;
	FILE *cpuinfo;

	cpuinfo = fopen(CPUINFO, "r");
	if (cpuinfo == NULL)
		return cpuid;

	while ((read = getline(&line, &line_sz, cpuinfo)) != -1) {
		if (!strncmp(line, CPUINFO_MVEN, strlen(CPUINFO_MVEN))) {
			mvendorid = _get_field(line);
			if (!mvendorid)
				goto free;
		} else if (!strncmp(line, CPUINFO_MARCH, strlen(CPUINFO_MARCH))) {
			marchid = _get_field(line);
			if (!marchid)
				goto free;
		} else if (!strncmp(line, CPUINFO_MIMP, strlen(CPUINFO_MIMP))) {
			mimpid = _get_field(line);
			if (!mimpid)
				goto free;

			break;
		}
	}

	if (!mvendorid || !marchid || !mimpid) {
		cpuid = NULL;
		goto free;
	}

	if (asprintf(&cpuid, "%s-%s-%s", mvendorid, marchid, mimpid) < 0)
		cpuid = NULL;

free:
	fclose(cpuinfo);

	if (mvendorid)
		free(mvendorid);

	if (marchid)
		free(marchid);

	if (mimpid)
		free(mimpid);

	return cpuid;
}

int get_cpuid(char *buffer, size_t sz)
{
	char *cpuid = _get_cpuid();

	if (sz < strlen(cpuid)) {
		free(cpuid);
		return -EINVAL;
	}

	scnprintf(buffer, sz, "%s", cpuid);
	return 0;
}

char *
get_cpuid_str(struct perf_pmu *pmu __maybe_unused)
{
	return _get_cpuid();
}
