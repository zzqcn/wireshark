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
#include <epan/reassemble.h>

#define FOO_PORT 1235

static int proto_foo = -1;

static int hf_foo_flags = -1;
static int hf_foo_seq = -1;
static int hf_foo_frag = -1;
static int hf_foo_fragments = -1;
static int hf_foo_fragment = -1;
static int hf_foo_fragment_overlap = -1;
static int hf_foo_fragment_overlap_conflict = -1;
static int hf_foo_fragment_multiple_tails = -1;
static int hf_foo_fragment_too_long_fragment = -1;
static int hf_foo_fragment_error = -1;
static int hf_foo_fragment_count = -1;
static int hf_foo_reassembled_in = -1;
static int hf_foo_reassembled_length = -1;
static int hf_foo_reassembled_data = -1;

#define FOO_FRAG_FLAG 0x01
#define FOO_LAST_FRAG_FLAG 0x02

static gint ett_foo = -1;
static gint ett_foo_fragment = -1;
static gint ett_foo_fragments = -1;

static reassembly_table foo_reassembly_table;

static const fragment_items foo_frag_items = {
    /* Fragment subtrees */
    &ett_foo_fragment,
    &ett_foo_fragments,
    /* Fragment fields */
    &hf_foo_fragments,
    &hf_foo_fragment,
    &hf_foo_fragment_overlap,
    &hf_foo_fragment_overlap_conflict,
    &hf_foo_fragment_multiple_tails,
    &hf_foo_fragment_too_long_fragment,
    &hf_foo_fragment_error,
    &hf_foo_fragment_count,
    /* Reassembled in field */
    &hf_foo_reassembled_in,
    /* Reassembled length field */
    &hf_foo_reassembled_length,
    /* Reassembled data field */
    &hf_foo_reassembled_data,
    /* Tag */
    "FOO fragments",
};

static int
dissect_foo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    tvbuff_t *next_tvb;
    guint16 seq_id, frag_id;
    guint8 flags;
    gboolean save_fragmented;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FOO2");
    /* Clear the info column */
    // col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_foo, tvb, 0, -1, ENC_NA);
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);

    seq_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(foo_tree, hf_foo_seq, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    frag_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(foo_tree, hf_foo_frag, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(foo_tree, hf_foo_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    save_fragmented = pinfo->fragmented;

    if (flags & FOO_FRAG_FLAG)
    { /* fragmented */
        tvbuff_t *new_tvb = NULL;
        fragment_head *frag_msg = NULL;

        pinfo->fragmented = TRUE;
        frag_msg = fragment_add_seq_check(&foo_reassembly_table,
                                          tvb, offset, pinfo,
                                          seq_id, NULL, frag_id,
                                          tvb_captured_length_remaining(tvb, offset),
                                          !(flags & FOO_LAST_FRAG_FLAG));

        new_tvb = process_reassembled_data(tvb, offset, pinfo,
                                           "Reassembled Message", frag_msg, &foo_frag_items,
                                           NULL, foo_tree);

        if (frag_msg)
        { /* Reassembled */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Message Reassembled in #%u)", frag_msg->frame);
        }
        else
        { /* Not last packet of reassembled Short Message */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %u)", frag_id);
        }

        if (new_tvb)
        { /* take it all */
            next_tvb = new_tvb;
        }
        else
        { /* make a new subset */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
        }
    }
    else
    { /* Not fragmented */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    pinfo->fragmented = save_fragmented;

    return tvb_captured_length(tvb);
}

void proto_register_foo(void)
{
    static hf_register_info hf[] = {
        {
            &hf_foo_seq,
            {
                "Message Number",
                "foo.msg_id",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_frag,
            {
                "Fragment Number",
                "foo.frag_id",
                FT_UINT16,
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
            &hf_foo_fragments,
            {
                "Fragments",
                "foo.fragments",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_fragment,
            {
                "Fragment",
                "foo.fragment",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_fragment_overlap,
            {
                "Fragment overlap",
                "foo.fragment.overlap",
                FT_BOOLEAN,
                0,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_fragment_overlap_conflict,
            {
                "Fragment overlapping with conflicting data",
                "foo.fragment.overlap.conflict",
                FT_BOOLEAN,
                0,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_fragment_multiple_tails,
            {
                "Has multiple tail fragments",
                "foo.fragment.multiple_tails",
                FT_BOOLEAN,
                0,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_fragment_too_long_fragment,
            {
                "Fragment too long",
                "foo.fragment.too_long_fragment",
                FT_BOOLEAN,
                0,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_fragment_error,
            {
                "Defragmentation error",
                "foo.fragment.error",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_fragment_count,
            {
                "Fragment count",
                "foo.fragment.count",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_reassembled_in,
            {
                "Reassembled in",
                "foo.reassembled.in",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_reassembled_length,
            {
                "Reassembled length",
                "foo.reassembled.length",
                FT_UINT32,
                BASE_DEC,
                NULL,
                0x00,
                NULL,
                HFILL,
            },
        },
        {
            &hf_foo_reassembled_data,
            {
                "Reassembled data",
                "foo.reassembled.data",
                FT_BYTES,
                BASE_NONE,
                NULL,
                0x0,
                "The reassembled payload",
                HFILL,
            },
        },
    };

    static gint *ett[] = {
        &ett_foo,
        &ett_foo_fragment,
        &ett_foo_fragments,
    };

    proto_foo = proto_register_protocol("Foo Protocol V2", "FOO2", "foo2");

    proto_register_field_array(proto_foo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    reassembly_table_register(&foo_reassembly_table,
                              &addresses_ports_reassembly_table_functions);
}

void proto_reg_handoff_foo(void)
{
    static dissector_handle_t foo_handle;

    foo_handle = create_dissector_handle(dissect_foo, proto_foo);
    dissector_add_uint("udp.port", FOO_PORT, foo_handle);
}
