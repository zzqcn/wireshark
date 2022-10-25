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

#define FOO_PORT 1234

static int proto_foo = -1;

static int hf_foo_type = -1;
static int hf_foo_flags = -1;
static int hf_foo_seq = -1;
static int hf_foo_ipaddr = -1;
static int hf_foo_startflag = -1;
static int hf_foo_endflag = -1;
static int hf_foo_priorityflag = -1;

static gint ett_foo = -1;

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

static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;
    guint8 packet_type = tvb_get_guint8(tvb, 0);

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
    offset += 2;
    proto_tree_add_item(foo_tree, hf_foo_ipaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return tvb_captured_length(tvb);
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
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {&ett_foo};

    proto_foo = proto_register_protocol("Foo Protocol", "FOO", "foo");

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}
