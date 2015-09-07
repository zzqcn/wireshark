/**
 * @file packet-dpi.c
 * @brief Routines for DPI
 * @author Zhao Ziqing <psyc209@163.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <assert.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
//#include <epan/dissectors/packet-tcp.h>
#include "packet-dpi.h"
#include "camrule.h"


//#define FOO_PORT    9877
#define FOO_NAME        "Haohan DPI"
#define FOO_SHORT_NAME  "DPI"
#define FOO_ABBREV      "dpi"


static int proto_dpi = -1;

static int hf_dpi_ptnId = -1;
static int hf_dpi_svcId = -1;
static int hf_dpi_ptnName = -1;
static int hf_dpi_ptn = -1;


static gint ett_dpi = -1;
camrule_ctx_t* g_cam_ctx = NULL;


void proto_register_dpi(void);
void proto_reg_handoff_dpi(void);
static int dissect_dpi(tvbuff_t*, packet_info*, proto_tree*, void*);



void
proto_register_dpi(void)
{
    static hf_register_info hf[] = 
    {
        {
            &hf_dpi_svcId,
            {
                "Service Id", "dpi.svcid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_dpi_ptnId,
            {
                "Pattern Id", "dpi.ptnid",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_dpi_ptnName,
            {
                "Pattern Name", "dpi.ptnname",
                FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_dpi_ptn,
            {
                "Matched Pattern", "dpi.ptn",
                FT_BYTES, BASE_NONE,
                NULL, 0x0, NULL, HFILL
            }
        }
    };
    
    static gint *ett[] = { &ett_dpi };
    int ret;
    
    proto_dpi = proto_register_protocol (
            FOO_NAME,
            FOO_SHORT_NAME,
            FOO_ABBREV);
            
    proto_register_field_array(proto_dpi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    g_cam_ctx = malloc(sizeof(camrule_ctx_t));
    assert(g_cam_ctx != NULL);
    camrule_ctx_init(g_cam_ctx);
    ret = camrule_ctx_load(g_cam_ctx, "ptndef.csv");
    assert(ret == 0);
}



static int
dissect_dpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    int ret;
    //guint16 svcid = 0;
    //guint8 packet_type = tvb_get_guint8(tvb, 0);
    //gchar *p, str[16] = {0};
    //GError *err = NULL;
    camrule_match_result_t result;
    
    (void)data;
    
    /* proto details display */
    if(tree)
    {
        proto_tree* dpi_tree = NULL;
        proto_tree* sub_tree = NULL;
        //gint offset = 0;
        gint mac_len = 14, ip_len, tran_len, hdr_len, tvb_len;
        guint8 payload[1500];
        //gchar* ptn = "weibo";

        dpi_tree = proto_tree_add_item(tree, proto_dpi, tvb, 0, -1, ENC_NA);
        dpi_tree = proto_item_add_subtree(dpi_tree, ett_dpi);

        ip_len = (tvb_get_guint8(tvb, 14) - 64) * 4;
        if(pinfo->ipproto == IP_PROTO_TCP)
        {
            tran_len = (tvb_get_guint8(tvb, 46) / 16) * 4;
        }
        else if(pinfo->ipproto == IP_PROTO_UDP)
        {
            tran_len = 8;
        }
        else
        {
            //proto_tree_add_item(dpi_tree, hf_dpi_svcId, NULL, 0, 0, ENC_NA);
            proto_item_append_text(dpi_tree, ", Don't care");
            goto END;
        }

        hdr_len = mac_len + ip_len + tran_len;
        tvb_len = tvb_reported_length_remaining(tvb, hdr_len);
        if(tvb_memcpy(tvb, payload, hdr_len, tvb_len) != NULL)
        {
            ret = camrule_ctx_match(g_cam_ctx, payload, tvb_len, &result);
            if(ret)
            {
                sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_svcId, tvb, 0, 0, result.rule->svcId);
                sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_ptnId, tvb, 0, 0, result.rule->ptnId);
                sub_tree = proto_tree_add_string(dpi_tree, hf_dpi_ptnName, tvb, 0, 0, result.rule->ptnName);
                proto_tree_add_item(dpi_tree, hf_dpi_ptn, tvb, hdr_len+result.start, 
                                        result.rule->cpl_ptn_len, ENC_NA);
                proto_item_append_text(dpi_tree, ", PtnId: %u", result.rule->ptnId);
                col_set_str(pinfo->cinfo, COL_PROTOCOL, result.rule->ptnName);
                goto END;
            }
        }
        
        
        /*
        for(i=hdr_len; i<tvb_len; i++)
        {
            if(tvb_memeql(tvb, i, ptn, strlen(ptn)) == 0)
            {
                svcid = 456;
                break;
            }  
        }*/
        
        sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_svcId, tvb, 0, 0, 0);
        PROTO_ITEM_SET_HIDDEN(sub_tree);
        sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_ptnId, tvb, 0, 0, 0);
        PROTO_ITEM_SET_HIDDEN(sub_tree);
        proto_item_append_text(dpi_tree, ", Unknown");
    }

END:
    //return tvb_reported_length(tvb);
    return tvb_length(tvb);
}

void
proto_reg_handoff_dpi(void)
{
    static dissector_handle_t dpi_handle;

    dpi_handle = new_create_dissector_handle(dissect_dpi, proto_dpi);
    //dissector_add_uint("udp.port", FOO_PORT, dpi_handle);
    register_postdissector(dpi_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
