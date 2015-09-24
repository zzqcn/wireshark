/**
 * @file packet-sniper.c
 * @brief Routines for sniper DPI
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
#ifdef _MSC_VER
  //#define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <glib.h>
#include <wiretap/wtap.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tvbuff-int.h>
#include <sp.h>
#include "packet-sniper.h"



#define DPI_NAME        "Haohan DPI"
#define DPI_SHORT_NAME  "DPI"
#define DPI_ABBREV      "dpi"



#define SNIPER_FLOW_MAX_NUM  102407

#define KNOWLEDGE_FILE_TYPE_DE 0 /*����֪ʶ��*/
#define KNOWLEDGE_FILE_TYPE_EN 1 /*����֪ʶ��*/

#define KNOWLEDGE_FILE_DEFAULT "sniper.klp"
#define KNOWLEDGE_FILE_MAXSIZE (1024*1024*16)



static int proto_dpi = -1;

static int hf_dpi_classId = -1;
static int hf_dpi_subclassId = -1;
static int hf_dpi_patternId = -1;
static int hf_dpi_ptnName = -1;
static int hf_dpi_ruleId = -1;


static gint ett_dpi = -1;



int sniper_load_klp(char *file,int type);
int sniper_init();

void proto_register_dpi(void);
void proto_reg_handoff_dpi(void);
static int dissect_dpi(tvbuff_t*, packet_info*, proto_tree*, void*);



void
proto_register_dpi(void)
{
    static hf_register_info hf[] = 
    {
        {
            &hf_dpi_classId,
            {
                "Class Id", "dpi.clsId",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_dpi_subclassId,
            {
                "Subclass Id", "dpi.subclsId",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_dpi_patternId,
            {
                "Pattern Id", "dpi.ptnId",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_dpi_ptnName,
            {
                "Pattern Name", "dpi.ptnName",
                FT_STRING, STR_UNICODE,
                NULL, 0x0, NULL, HFILL
            }
        },
        {
            &hf_dpi_ruleId,
            {
                "Rule Id", "dpi.ruleId",
                FT_UINT16, BASE_DEC,
                NULL, 0x0, NULL, HFILL
            }
        }
    };
    
    static gint *ett[] = { &ett_dpi };
    int ret;
    
    proto_dpi = proto_register_protocol (
            DPI_NAME,
            DPI_SHORT_NAME,
            DPI_ABBREV);
            
    proto_register_field_array(proto_dpi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    ret = sniper_init();
    assert(ret == 0);
}



static int
dissect_dpi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    int dpi_ret = 0;
    gint eth_t, mac_len = 14, ip_len, tran_len, hdr_len, tvb_len;
    //guint8 payload[1500];
    conversation_t* conv;
    SP_PACKET_S pkt;
    SP_UINT8 L3 = SP_L3PROTOCOL_ANY, L4 = SP_IPPROTO_ANY;
    port_type ptype;
    SP_IDENTRESULT_S *sp_result = NULL; 
    SP_INT32 err = SP_OK;
    
    (void)data;

    memset(&pkt, 0, sizeof(SP_PACKET_S));
    memset(&pinfo->dpi_info, 0, sizeof(dpi_t));

    //goto END;

    // XXX BUG: check it's an IP pkt.
    if(pinfo->fd->lnk_t != WTAP_ENCAP_ETHERNET)
        goto END;
    eth_t = tvb_get_ntohs(tvb, 12);
    if(eth_t != 0x0800)
        goto END;

    //goto END;

    ip_len = (tvb_get_guint8(tvb, 14) - 64) * 4;
    tran_len = 0;
    if(pinfo->ipproto == IP_PROTO_TCP)
    {
        L4 = SP_IPPROTO_TCP;
        ptype = PT_TCP;
        tran_len = (tvb_get_guint8(tvb, 46) / 16) * 4;
    }
    else if(pinfo->ipproto == IP_PROTO_UDP)
    {
        L4 = SP_IPPROTO_UDP;
        ptype = PT_UDP;
        tran_len = 8;
    }
    else
    {
        if(!tree)
            goto END;
    }

    hdr_len = mac_len + ip_len + tran_len;
    tvb_len = tvb_reported_length_remaining(tvb, hdr_len);

    // construct SP_PACKET_S
    // XXX BUG!!!
    pkt.EthHdr = (const SP_UINT8*)tvb->real_data;
    pkt.IpHdr = (const SP_UINT8*)(tvb->real_data + mac_len);
    // XXX BUG: don't support ipv6 yet
    pkt.TranHdr = (const SP_UINT8*)(tvb->real_data + mac_len + ip_len);
    pkt.Payload = tvb->real_data + mac_len + ip_len + tran_len;
    pkt.PayloadLen = tvb_len;
    if(pinfo->net_src.type == AT_IPv4 && pinfo->net_src.len == 4)
        memcpy(&pkt.SrcIp.Ip, pinfo->net_src.data, 4);
    if(pinfo->net_dst.type == AT_IPv4 && pinfo->net_dst.len == 4)
        memcpy(&pkt.DstIp.Ip, pinfo->net_dst.data, 4);
    pkt.SrcPort = pinfo->srcport;
    pkt.DstPort = pinfo->destport;
    pkt.Dir = 0; // TODO
    pkt.Layer3 = L3;
    pkt.Layer4 = L4;


    conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, ptype, 
                pinfo->srcport, pinfo->destport, 0);
    if (conv == NULL)
    {
        conv = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, ptype,
                pinfo->srcport, pinfo->destport, 0);
        //conversation_set_dissector(conv, ftpdata_handle);
    }

    sp_result = &conv->dpi_result;
    if(pkt.PayloadLen > 0 && sp_result->Status != SP_IDENTSTATUS_KNOWN &&
       sp_result->Status != SP_IDENTSTATUS_UNKNOWN)
    {
        SP_HTTPANCHORINFO_S http_info;
        memset(&http_info, 0, sizeof(SP_HTTPANCHORINFO_S));
        err = SP_Ident(&pkt, &conv->dpi_private, sp_result, 0, &http_info, &conv->dpi_http_data); // 1 thread
        if(err != SP_OK)
            goto END;
    }

    if(sp_result->Status != SP_IDENTSTATUS_CONTINUE && 
       sp_result->Status != SP_IDENTSTATUS_UNKNOWN)
    {
        dpi_ret = 1;
        pinfo->dpi_info.valid = TRUE;
        pinfo->dpi_info.class_id = sp_result->ClassId;
        pinfo->dpi_info.subclass_id = sp_result->SubClassId;
        pinfo->dpi_info.pattern_id = sp_result->PatternId;
        pinfo->dpi_info.priority = sp_result->PtnPri;
        SP_GetPatternName(sp_result->PatternId, pinfo->dpi_info.pattern_name, NULL);

        col_set_str(pinfo->cinfo, COL_PROTOCOL, pinfo->dpi_info.pattern_name);
    }

    /* proto details display */
    if(tree)
    {
        proto_tree* dpi_tree = NULL;
        proto_tree* sub_tree = NULL;

        dpi_tree = proto_tree_add_item(tree, proto_dpi, tvb, 0, -1, ENC_NA);
        dpi_tree = proto_item_add_subtree(dpi_tree, ett_dpi);

        if(pinfo->ipproto != IP_PROTO_TCP && pinfo->ipproto != IP_PROTO_UDP)
        {
            proto_item_append_text(dpi_tree, ", Don't care");
            goto END;
        }

        if(dpi_ret)
        {
            sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_classId, tvb, 0, 0, pinfo->dpi_info.class_id);
            sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_patternId, tvb, 0, 0, pinfo->dpi_info.pattern_id);
            sub_tree = proto_tree_add_string(dpi_tree, hf_dpi_ptnName, tvb, 0, 0, pinfo->dpi_info.pattern_name);
            //proto_tree_add_item(dpi_tree, hf_dpi_ptn, tvb, hdr_len+result.start, 
            //                        result.rule->cpl_ptn_len, ENC_NA);
            
            sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_ruleId, tvb, 0, 0, sp_result ? sp_result->RuleId:0);
            proto_item_append_text(dpi_tree, ", PtnId: %u", pinfo->dpi_info.pattern_id);
            goto END;
        }
        
        sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_classId, tvb, 0, 0, 0);
        PROTO_ITEM_SET_HIDDEN(sub_tree);
        sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_patternId, tvb, 0, 0, 0);
        PROTO_ITEM_SET_HIDDEN(sub_tree);
        sub_tree = proto_tree_add_uint(dpi_tree, hf_dpi_ruleId, tvb, 0, 0, 0);
        PROTO_ITEM_SET_HIDDEN(sub_tree);
        proto_item_append_text(dpi_tree, ", Unknown");
    }

END:
    //return tvb_reported_length(tvb);
    return tvb_captured_length(tvb);
}

void
proto_reg_handoff_dpi(void)
{
    static dissector_handle_t dpi_handle;

    dpi_handle = new_create_dissector_handle(dissect_dpi, proto_dpi);
    register_postdissector(dpi_handle);
}


int sniper_init()
{
    int ret = 0;
    SP_HLIB_CALLBACK_S cb = {0};
    SP_UINT64 mem_size;
    SP_UINT8* mem;

    cb.Malloc = malloc;
    cb.Memset = memset;
    cb.Free = free;
    cb.Memcpy = memcpy;
    cb.Memcmp = memcmp;
    cb.Memmove = memmove;
    cb.Memchr = memchr;

    cb.Strtol = strtol;
    cb.Strtoul = strtoul;
    cb.Printf = printf;
    cb.Sprintf = sprintf;
    cb.Snprintf = _snprintf;
    cb.Scanf = scanf;
    cb.Sscanf = sscanf;

    /*cb.SP_MutexInit = mutex_init;
    cb.SP_MutexLock = mutex_lock;
    cb.SP_MutexTryLock = mutex_trylock;
    cb.SP_MutexUnlock = mutex_unlock;
    cb.SP_MutexDestroy = mutex_destroy;

    cb.SP_SpinInit = spin_init;
    cb.SP_SpinLock = spin_lock;
    cb.SP_SpinUnlock = spin_unlock;
    cb.SP_SpinDestroy = spin_destroy;

    cb.SP_Rwlock_Init = rwlock_init;
    cb.SP_Rwlock_RdLock = rwlock_rdlock;
    cb.SP_Rwlock_TryRdLock = rwlock_tryrdlock;
    cb.SP_Rwlock_WrLock = rwlock_wrlock;
    cb.SP_Rwlock_TryWrLock = rwlock_trywrlock;
    cb.SP_Rwlock_RdUnLock = rwlock_rdunlock;
    cb.SP_Rwlock_WrUnLock = rwlock_wrunlock;
    cb.SP_Rwlock_Destroy = rwlock_destroy;*/

    cb.GetNowTime = time;

    ret = SP_RegCallBack(&cb);
    if (ret != SP_OK)
    {
        fprintf(stderr, "SP_RegCallBack fail,ERRCODE[0x%0x]\n",ret);
        return -1;
    }

    ret = SP_GetMemTotalSize(SNIPER_FLOW_MAX_NUM, &mem_size);
    if (ret != SP_OK)
    {
        fprintf(stderr, "SP_GetMemTotalSize fail,ERRCODE[0x%0x]\n",ret);
        return -1;
    }

    mem = (SP_UINT8*) malloc(mem_size);
    if (NULL == mem)
    {
        fprintf(stderr, "bad alloc, need size: %llu\n", mem_size);
        return -1;
    }

    ret = SP_Init((SP_INT8*)mem, mem_size, SNIPER_FLOW_MAX_NUM);
    if (ret != SP_OK)
    {
        fprintf(stderr, "SP_Init fail, ERRCODE[0x%0x]\n",ret);
        return -1;
    }
    ret = sniper_load_klp(KNOWLEDGE_FILE_DEFAULT, KNOWLEDGE_FILE_TYPE_DE);
    if (ret != SP_OK)
    {
        fprintf(stderr, "please mod %s\n" ,KNOWLEDGE_FILE_DEFAULT);
    }

    return 0;
}


int sniper_load_klp(char *file,int type)
{
    char *mem = NULL;
    FILE *fp = NULL;
    long flen;
    int ret = 0;
    //DWORD at, et;

    if(NULL == file)
        return -1;

    fp = fopen(file, "rb");
    if(NULL == fp)
    {
        printf("can't open %s\n", file);
        return -1;
    }

    fseek(fp, 0L, SEEK_END);
    flen = ftell(fp);
    if(flen > KNOWLEDGE_FILE_MAXSIZE)
        goto CLOSE;
    fseek(fp, 0L, SEEK_SET);

    mem = (char*) malloc(flen);
    if (!mem) {
        printf("err:%s\n", "Malloc for LoadKnowLedge");
        return -1;
    }
    memset(mem, 0, flen);

    ret = fread(mem, 1, flen, fp);
    if(ret != flen)
    {
        printf("Fail to write into buffer,size = %l, ret = %u\n",
            flen, ret);
        goto CLOSE;
    }

    //at = GetTickCount();
    if(KNOWLEDGE_FILE_TYPE_EN == type)
        ret = SP_LoadEncKnowLedge(mem, flen);
    else
        ret = SP_LoadKnowLedge(mem, flen);
    if(ret != SP_OK)
    {
        printf("SP_LoadKnowLedge fail,ERRCODE[0x%0x]\n",ret);
        goto CLOSE;
    }
    //et = GetTickCount();
    //printf("LoadLibTime   :%f(ms)\n", (et-at));
    printf("LoadKnowLedge is ok :%s\n", file);

    fclose(fp);
    free(mem);

    return 0;

CLOSE:
    fclose(fp);

    free(mem);
    return -1;
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
