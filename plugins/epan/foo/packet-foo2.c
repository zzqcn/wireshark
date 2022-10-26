/* packet-foo2.c
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

static gint ett_foo = -1;

static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO");
    /* Clear the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(foo_tree, hf_foo_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
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
                NULL,
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
    };

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
