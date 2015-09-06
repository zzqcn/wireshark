/* packet-text-media.c
 * Routines for text-based media dissection.
 *
 * NOTE - The media type is either found in pinfo->match_string,
 *        pinfo->private_data, or passed into the dissector (preferred)
 *
 * (C) Olivier Biot, 2004.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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

/* Edit this file with 4-space tabs */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>


/*
 * Media dissector for line-based text media like text/plain, message/http.
 *
 * TODO - character set and chunked transfer-coding
 */
void proto_register_text_lines(void);
void proto_reg_handoff_text_lines(void);

/* Filterable header fields */
static gint proto_text_lines = -1;

/* Subtrees */
static gint ett_text_lines = -1;

/* Dissector handles */
static dissector_handle_t xml_handle;

static int
dissect_text_lines(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	proto_tree	*subtree;
	proto_item	*ti;
	gint		offset = 0, next_offset;
	gint		len;
	const char	*data_name;
	int length = tvb_length(tvb);

	/* Check if this is actually xml
	 * If there is less than 38 characters this is not XML
	 * <?xml version="1.0" encoding="UTF-8"?>
	 */
	if(length > 38){
		if (tvb_strncaseeql(tvb, 0, "<?xml", 5) == 0){
			call_dissector(xml_handle, tvb, pinfo, tree);
			return tvb_length(tvb);
		}
	}

	data_name = pinfo->match_string;
	if (! (data_name && data_name[0])) {
		/*
		 * No information from "match_string"
		 */
		data_name = (char *)data;
		if (! (data_name && data_name[0])) {
			/*
			 * No information from dissector data
			 */
			data_name = (char *)(pinfo->private_data);
			if (! (data_name && data_name[0])) {
				/*
				 * No information from "private_data"
				 */
				data_name = NULL;
			}
		}
	}

	if (data_name)
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(%s)",
				data_name);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_text_lines,
				tvb, 0, -1, ENC_NA);
		if (data_name)
			proto_item_append_text(ti, ": %s", data_name);
		subtree = proto_item_add_subtree(ti, ett_text_lines);
		/* Read the media line by line */
		while (tvb_offset_exists(tvb, offset)) {
			/*
			 * XXX - we need to be passed the parameters
			 * of the content type via "pinfo->private_data",
			 * so that we know the character set.  We'd
			 * have to handle that character set, which
			 * might be a multibyte character set such
			 * as "iso-10646-ucs-2", or might require other
			 * special processing.
			 */
			len = tvb_find_line_end(tvb, offset,
					tvb_ensure_length_remaining(tvb, offset),
					&next_offset, FALSE);
			if (len == -1)
				break;

			/* We use next_offset - offset instead of len in the
			 * call to proto_tree_add_format_text() so it will include the
			 * line terminator(s) (\r and/or \n) in the display.
			 */
			proto_tree_add_format_text(subtree, tvb, offset, next_offset - offset);
			offset = next_offset;
		}
	}

	return tvb_length(tvb);
}

void
proto_register_text_lines(void)
{
	static gint *ett[] = {
		&ett_text_lines,
	};

	proto_register_subtree_array(ett, array_length(ett));

	proto_text_lines = proto_register_protocol(
			"Line-based text data",	/* Long name */
			"Line-based text data",	/* Short name */
			"data-text-lines");		/* Filter name */
	new_register_dissector("data-text-lines", dissect_text_lines, proto_text_lines);
}

void
proto_reg_handoff_text_lines(void)
{
	dissector_handle_t text_lines_handle;

	text_lines_handle = find_dissector("data-text-lines");

	dissector_add_string("media_type", "text/plain", text_lines_handle); /* RFC 2046 */
	dissector_add_string("media_type", "text/richtext", text_lines_handle);  /* RFC 1341 */
	dissector_add_string("media_type", "text/enriched", text_lines_handle);  /* RFC 1896 */
	dissector_add_string("media_type", "text/parameters", text_lines_handle);
	/* W3C line-based textual media */
	dissector_add_string("media_type", "text/html", text_lines_handle);
	dissector_add_string("media_type", "text/xml-external-parsed-entity", text_lines_handle);
	dissector_add_string("media_type", "text/css", text_lines_handle);
	dissector_add_string("media_type", "application/xml-external-parsed-entity", text_lines_handle);
	dissector_add_string("media_type", "text/javascript", text_lines_handle);
	dissector_add_string("media_type", "application/x-javascript", text_lines_handle);
	dissector_add_string("media_type", "application/x-tia-p25-issi", text_lines_handle);
	dissector_add_string("media_type", "application/x-tia-p25-sndcp", text_lines_handle);
	dissector_add_string("media_type", "application/x-ns-proxy-autoconfig", text_lines_handle);

	dissector_add_string("media_type", "text/vnd.sun.j2me.app-descriptor", text_lines_handle);
	dissector_add_string("media_type", "application/vnd.poc.refer-to", text_lines_handle);
	dissector_add_string("media_type", "application/vnd.drm.message", text_lines_handle);

	dissector_add_string("media_type", "application/x-wms-logplaystats", text_lines_handle);
	dissector_add_string("media_type", "application/x-rtsp-udp-packetpair", text_lines_handle);
	xml_handle = find_dissector("xml");
}
