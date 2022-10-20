/* packet-gryphon.c
 *
 * Updated routines for Gryphon protocol packet dissection
 * By Mark C. <markc@dgtech.com>
 * Copyright (C) 2018 DG Technologies, Inc. (Dearborn Group, Inc.) USA
 *
 * Routines for Gryphon protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification: http://www.dgtech.com/product/gryphon/manual/html/GCprotocol/
 *
 */

#include "config.h"

#include <wsutil/filesystem.h>
#include <epan/packet.h>
#include "packet-dpi.h"

void proto_register_dpi(void);
void proto_reg_handoff_dpi(void);

static int proto_dpi = -1;
static int proto_http = -1;
static int hf_http_host = -1;

static int hf_dpi_ptn_id = -1;
static int hf_dpi_ptn_name = -1;
static int hf_dpi_ptn_val = -1;

static gint ett_dpi = -1;

static int
dissect_dpi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    if (tree)
    {
        proto_tree *ti = tree->first_child;
        while (ti != NULL)
        {
            if (ti->finfo->hfinfo->type == FT_PROTOCOL && ti->finfo->hfinfo->id == proto_http)
            {
                ti = ti->first_child;
                while (ti != NULL)
                {
                    if (ti->finfo->hfinfo->id == hf_http_host)
                    {
                        dpi_rule_t *rule;
                        proto_tree *dpi_tree =
                            proto_tree_add_item(tree, proto_dpi, tvb, 0, -1, ENC_NA);

                        tvbuff_t* ds;
                        ds = get_data_source_tvb_by_name(pinfo, "Reassembled TCP");
                        if (NULL == ds)
                            ds = tvb;

                        rule = dpi_match(ti->finfo->rep->representation, (uint32_t)strlen(ti->finfo->rep->representation));
                        if (rule != NULL)
                        {
                            proto_item_add_subtree(dpi_tree, ett_dpi);
                            proto_tree_add_uint(dpi_tree, hf_dpi_ptn_id, ds, 0, 0, rule->id);
                            proto_tree_add_string(dpi_tree, hf_dpi_ptn_name, ds, ti->finfo->start, ti->finfo->length, rule->name);
                            proto_item_append_text(dpi_tree, ", match %s", rule->name);
                        }
                        else
                        {
                            proto_item_append_text(dpi_tree, ", no match");
                        }
                        break;
                    }
                    ti = ti->next;
                }

                break;
            }
            ti = ti->next;
        }
    }

    return tvb_reported_length(tvb);
}

void proto_register_dpi(void)
{
    static hf_register_info hf[] =
        {
            {&hf_dpi_ptn_id,
             {
                 "Pattern Id",
                 "dpi.ptn_id",
                 FT_UINT32,
                 BASE_DEC,
                 NULL,
                 0x0,
                 NULL,
                 HFILL,
             }},
            {&hf_dpi_ptn_name,
             {
                 "Pattern Name",
                 "dpi.ptn_name",
                 FT_STRING,
                 BASE_NONE,
                 NULL,
                 0x0,
                 NULL,
                 HFILL,
             }},
            {&hf_dpi_ptn_val,
             {
                 "Matched Pattern",
                 "dpi.ptn_val",
                 FT_BYTES,
                 BASE_NONE,
                 NULL,
                 0x0,
                 NULL,
                 HFILL,
             }},
        };

    int ret;
    static gint *ett[] = {&ett_dpi};
    char path[PATH_MAX];

    proto_dpi = proto_register_protocol("Deep Packet Inspection", "DPI", "dpi");

    proto_register_field_array(proto_dpi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    snprintf(path, PATH_MAX, "%s/rules.txt", get_progfile_dir());
    ret = dpi_load_rules(path);
    if (ret != 0)
        ws_error("load DPI rules failed");
}

void proto_reg_handoff_dpi(void)
{
    static dissector_handle_t dpi_handle;

    proto_http = proto_get_id_by_filter_name("http");
    hf_http_host = proto_registrar_get_id_byname("http.host");

    dpi_handle = create_dissector_handle(dissect_dpi, proto_dpi);
    register_postdissector(dpi_handle);
}
