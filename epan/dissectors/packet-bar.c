/* packet-bar.c
 * Routines for Bar dissection
 * Copyright 2022, zzqcn <psyc209@163.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * A very simple built-in protocol dissector demo.
 * See my article https://www.yuque.com/zzqcn/wireshark/snyg6w for details.
 */

#include "config.h"

#include <epan/packet.h>

#define BAR_PORT 9527

static int proto_bar = -1;
static dissector_handle_t bar_handle;

static int
dissect_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BAR");

    proto_tree_add_item(tree, proto_bar, tvb, 0, -1, ENC_NA);

    return tvb_captured_length(tvb);
}

void proto_register_bar(void)
{
    proto_bar = proto_register_protocol("BAR Protocol", "Bar", "bar");
    bar_handle = register_dissector("bar", dissect_bar, proto_bar);
}

void proto_reg_handoff_bar(void)
{
    dissector_add_uint("tcp.port", BAR_PORT, bar_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
