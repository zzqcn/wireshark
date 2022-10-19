/* packet-dpi.h
 *
 * DPI demo
 * By zzqcn <psyc209@163.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdint.h>

#ifndef PATH_MAX
#define PATH_MAX 512
#endif

#ifndef LINE_MAX
#define LINE_MAX 1024
#endif

#define DPI_MAX_RULES 64

typedef struct dpi_rule
{
    uint32_t id;
    char host[32];
    uint16_t priority;
    char name[32];
} dpi_rule_t;

int dpi_load_rules(const char *rule_path);
dpi_rule_t *dpi_match(const char *data, uint32_t data_len);
