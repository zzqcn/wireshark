/* packet-foo3.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>
#include <epan/conversation.h>

#define FOO_MAGIC 0xfee1900d
#define FOO_MIN_LEN 12

static int proto_foo = -1;

static int foo_tap = -1;

static int hf_foo_type = -1;
static int hf_foo_flags = -1;
static int hf_foo_seq = -1;
static int hf_foo_ipaddr = -1;
static int hf_foo_startflag = -1;
static int hf_foo_endflag = -1;
static int hf_foo_priorityflag = -1;
static int hf_foo_first_packet = -1;

static gint ett_foo = -1;

static gboolean foo_show_first_packet = TRUE;

#define FOO_START_FLAG 0x01
#define FOO_END_FLAG 0x02
#define FOO_PRIORITY_FLAG 0x04

static const value_string foo_type_names[] = {
    {1, "Initialise"},
    {2, "Terminate"},
    {3, "Data"},
    {0, NULL},
};

static int *const bits[] = {
    &hf_foo_startflag,
    &hf_foo_endflag,
    &hf_foo_priorityflag,
    NULL,
};

typedef struct foo_tap
{
    gint packet_type;
    gint seq;
} foo_tap_t;

typedef struct foo_conv
{
    guint32 first_packet;
} foo_conv_t;

static int
dissect_foo_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    guint8 packet_type = tvb_get_guint8(tvb, offset);
    guint16 seq;
    foo_tap_t *foo_info;
    conversation_t *conv = NULL;
    foo_conv_t *conv_data = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",
                 val_to_str(packet_type, foo_type_names, "Unknown (0x%02x)"));

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type %s",
                           val_to_str(packet_type, foo_type_names, "Unknown (0x%02x)"));
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(foo_tree, hf_foo_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    // proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bitmask(foo_tree, tvb, offset, hf_foo_flags, ett_foo, bits, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
    seq = tvb_get_ntohs(tvb, offset);
    offset += 2;
    proto_tree_add_item(foo_tree, hf_foo_ipaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    conv = find_conversation(pinfo->num, &pinfo->src, &pinfo->dst,
                             pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    if (conv)
        conv_data = (foo_conv_t *)conversation_get_proto_data(conv, proto_foo);
    if (NULL == conv_data)
    {
        conv_data = wmem_alloc(wmem_file_scope(), sizeof(conv_data));
        conv_data->first_packet = pinfo->num;
        conversation_add_proto_data(conv, proto_foo, (void *)conv_data);
    }
    else
    {
        if (foo_show_first_packet)
            proto_tree_add_uint(foo_tree, hf_foo_first_packet, tvb, 0, 12, conv_data->first_packet);
    }

    foo_info = wmem_alloc(pinfo->pool, sizeof(foo_tap_t));
    foo_info->packet_type = packet_type;
    foo_info->seq = seq;
    tap_queue_packet(foo_tap, pinfo, foo_info);

    return tvb_captured_length(tvb);
}

static gboolean
dissect_foo_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint32 magic;

    if (tvb_captured_length(tvb) < FOO_MIN_LEN)
        return FALSE;

    magic = tvb_get_ntohl(tvb, 0);
    if (magic != FOO_MAGIC)
        return FALSE;

    dissect_foo_common(tvb, pinfo, tree, 4);

    return TRUE;
}

static const guint8 *st_str_packets = "Total Packets";
static const guint8 *st_str_packet_types = "FOO Packet Types";
static int st_node_packets = -1;
static int st_node_packet_types = -1;

static void foo_stats_tree_init(stats_tree *st)
{
    st_node_packets = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, TRUE);
    st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static tap_packet_status foo_stats_tree_packet(stats_tree *st, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *p, tap_flags_t flags _U_)
{
    foo_tap_t *pi = (foo_tap_t *)p;
    tick_stat_node(st, st_str_packets, 0, FALSE);
    stats_tree_tick_pivot(st, st_node_packet_types,
                          val_to_str(pi->packet_type, foo_type_names, "Unknown packet type (%d)"));
    return TAP_PACKET_REDRAW;
}

void proto_register_foo(void)
{
    static hf_register_info hf[] = {
        {
            &hf_foo_type,
            {
                "Type",
                "foo.type",
                FT_UINT8,
                BASE_DEC,
                VALS(foo_type_names),
                0x0,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_flags,
            {
                "Flags",
                "foo.flags",
                FT_UINT8,
                BASE_HEX,
                NULL,
                0x0,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_seq,
            {
                "Sequence Number",
                "foo.seq",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_ipaddr,
            {
                "IP Address",
                "foo.ipaddr",
                FT_IPv4,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_startflag,
            {
                "Start Flag",
                "foo.flags.start",
                FT_BOOLEAN,
                8,
                NULL,
                FOO_START_FLAG,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_endflag,
            {
                "End Flag",
                "foo.flags.end",
                FT_BOOLEAN,
                8,
                NULL,
                FOO_END_FLAG,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_priorityflag,
            {
                "Priority Flag",
                "foo.flags.priority",
                FT_BOOLEAN,
                8,
                NULL,
                FOO_PRIORITY_FLAG,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_first_packet,
            {
                "FirstPacket",
                "foo.first_packet",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL,
            },
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {&ett_foo};

    proto_foo = proto_register_protocol("Foo Protocol", "FOO", "foo");

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module_t *foo_pref = prefs_register_protocol(proto_foo, NULL);
    prefs_register_bool_preference(foo_pref, "show_first_packet",
                                   "Show first packet number",
                                   NULL,
                                   &foo_show_first_packet);

    foo_tap = register_tap("foo");
    stats_tree_register_plugin("foo", "foo", "Foo/Packet Types", 0,
                               foo_stats_tree_packet, foo_stats_tree_init, NULL);
}

void proto_reg_handoff_foo(void)
{
    heur_dissector_add("udp", dissect_foo_heur, "FOO over UDP", "foo_udp", proto_foo, HEURISTIC_ENABLE);
}
