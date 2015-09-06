/*
 * k12.c
 *
 *  routines for importing tektronix k12xx *.rf5 files
 *
 *  Copyright (c) 2005, Luis E. Garia Ontanon <luis@ontanon.org>
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "wtap-int.h"
#include "wtap.h"
#include "file_wrappers.h"
#include <wsutil/buffer.h>
#include "k12.h"

#include <wsutil/str_util.h>

/*
 * See
 *
 *  http://www.tek.com/manual/record-file-api-programmer-manual
 *
 * for some information about the file format.  You may have to fill in
 * a form to download the document ("Record File API Programmer Manual").
 *
 * Unfortunately, it describes an API that delivers records from an rf5
 * file, not the raw format of an rf5 file, so, while it gives the formats
 * of the records with various types, it does not indicate how those records
 * are stored in the file.
 */

/* #define DEBUG_K12 */
#ifdef DEBUG_K12
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <wsutil/file_util.h>

FILE* dbg_out = NULL;
char* env_file = NULL;

static unsigned int debug_level = 0;

void k12_fprintf(const char* fmt, ...) {
    va_list ap;

    va_start(ap,fmt);
    vfprintf(dbg_out, fmt, ap);
    va_end(ap);
}

#define CAT(a,b) a##b
#define K12_DBG(level,args) do { if (level <= debug_level) { \
	fprintf(dbg_out,"%s:%d: ",CAT(__FI,LE__),CAT(__LI,NE__)); \
	k12_fprintf args ; \
	fprintf(dbg_out,"\n"); \
} } while(0)

void k12_hex_ascii_dump(guint level, gint64 offset, const char* label, const unsigned char* b, unsigned int len) {
    static const char* c2t[] = {
        "00","01","02","03","04","05","06","07","08","09","0a","0b","0c","0d","0e","0f",
        "10","11","12","13","14","15","16","17","18","19","1a","1b","1c","1d","1e","1f",
        "20","21","22","23","24","25","26","27","28","29","2a","2b","2c","2d","2e","2f",
        "30","31","32","33","34","35","36","37","38","39","3a","3b","3c","3d","3e","3f",
        "40","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f",
        "50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f",
        "60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f",
        "70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f",
        "80","81","82","83","84","85","86","87","88","89","8a","8b","8c","8d","8e","8f",
        "90","91","92","93","94","95","96","97","98","99","9a","9b","9c","9d","9e","9f",
        "a0","a1","a2","a3","a4","a5","a6","a7","a8","a9","aa","ab","ac","ad","ae","af",
        "b0","b1","b2","b3","b4","b5","b6","b7","b8","b9","ba","bb","bc","bd","be","bf",
        "c0","c1","c2","c3","c4","c5","c6","c7","c8","c9","ca","cb","cc","cd","ce","cf",
        "d0","d1","d2","d3","d4","d5","d6","d7","d8","d9","da","db","dc","dd","de","df",
        "e0","e1","e2","e3","e4","e5","e6","e7","e8","e9","ea","eb","ec","ed","ee","ef",
        "f0","f1","f2","f3","f4","f5","f6","f7","f8","f9","fa","fb","fc","fd","fe","ff"
    };
    unsigned int i, j;

    if (debug_level < level) return;

    fprintf(dbg_out,"%s(%.8" G_GINT64_MODIFIER "x,%.4x):\n",label,offset,len);

    for (i=0 ; i<len ; i += 16) {
        for (j=0; j<16; j++) {
            if ((j%4)==0)
                fprintf(dbg_out," ");
            if ((i+j)<len)
                fprintf(dbg_out, "%s", c2t[b[i+j]]);
            else
                fprintf(dbg_out, "  ");
        }
        fprintf(dbg_out, "    ");
        for (j=0; j<16; j++) {
            if ((i+j)<len)
                fprintf(dbg_out, "%c", g_ascii_isprint(b[i+j]) ? b[i+j] : '.');
        }
        fprintf(dbg_out,"\n");
    }
}

#define K12_HEX_ASCII_DUMP(x,a,b,c,d) k12_hex_ascii_dump(x,a,b,c,d)

void k12_ascii_dump(guint level, guint8 *buf, guint32 len, guint32 buf_offset) {
    guint32 i;

    if (debug_level < level) return;

    for (i = buf_offset; i < len; i++) {
        if (g_ascii_isprint(buf[i]) || buf[i] == '\n' || buf[i] == '\t')
            putc(buf[i], dbg_out);
        else if (buf[i] == '\0')
            fprintf(dbg_out, "(NUL)\n");
    }
}

#define K12_ASCII_DUMP(x,a,b,c) k12_ascii_dump(x,a,b,c)

#else
#define K12_DBG(level,args) (void)0
#define K12_HEX_ASCII_DUMP(x,a,b,c,d)
#define K12_ASCII_DUMP(x,a,b,c)
#endif



/*
 * the 32 bits .rf5 file contains:
 *  an 8 byte magic number
 *  32bit length
 *  32bit number of records
 *  other 0x200 bytes bytes of uncharted territory
 *     1 or more copies of the num_of_records in there
 *  the records whose first 32bits word is the length
 *     they are stuffed by one to four words every 0x2000 bytes
 *  and a 2 byte terminator FFFF
 */

static const guint8 k12_file_magic[] = { 0x00, 0x00, 0x02, 0x00 ,0x12, 0x05, 0x00, 0x10 };

typedef struct {
    guint32 file_len;
    guint32 num_of_records;   /* XXX: not sure about this */

    GHashTable* src_by_id;    /* k12_srcdsc_recs by input */
    GHashTable* src_by_name;  /* k12_srcdsc_recs by stack_name */

    guint8 *seq_read_buff;    /* read buffer for sequential reading */
    guint seq_read_buff_len;  /* length of that buffer */
    guint8 *rand_read_buff;   /* read buffer for random reading */
    guint rand_read_buff_len; /* length of that buffer */

    Buffer extra_info;        /* Buffer to hold per packet extra information */
} k12_t;

typedef struct _k12_src_desc_t {
    guint32 input;
    guint32 input_type;
    gchar* input_name;
    gchar* stack_file;
    k12_input_info_t input_info;
} k12_src_desc_t;


/*
 * According to the Tektronix documentation, this value is a combination of
 * a "group" code and a "type" code, with both being 2-byte values and
 * with the "group" code followe by the "type" code.  The "group" values
 * are:
 *
 *	0x0001 - "data event"
 *	0x0002 - "text or L1 event"
 *	0x0007 - "configuration event"
 *
 * and the "type" values are:
 *
 *  data events:
 *	0x0020 - "frame" (i.e., "an actual packet")
 *	0x0021 - "transparent frame"
 *	0x0022 - "bit data (TRAU frame)"
 *	0x0024 - "used to mark the frame which is a fragment"
 *	0x0026 - "used to mark the frame which is a fragment"
 *	0x0028 - "used to mark the frame which is generated by the LSA"
 *	0x002A - "used to mark the frame which is generated by the LSA"
 *
 *  text or L1 events:
 *	0x0030 - "text event"
 *	0x0031 - "L1 event"
 *	0x0032 - "L1 event (BAI)"
 *	0x0033 - "L1 event (VX)"
 *
 *  configuration events:
 *	0x0040 - Logical Data Source configuration event
 *	0x0041 - Logical Link configuration event
 */
/* so far we've seen these types of records */
#define K12_REC_PACKET        0x00010020 /* an actual packet */
#define K12_REC_D0020         0x000d0020 /* an actual packet, seen in a k18 file */
#define K12_REC_SCENARIO      0x00070040 /* what appears as the window's title */
#define K12_REC_SRCDSC        0x00070041 /* port-stack mapping + more, the key of the whole thing */
#define K12_REC_STK_FILE      0x00070042 /* a dump of an stk file */
#define K12_REC_SRCDSC2       0x00070043 /* another port-stack mapping */
#define K12_REC_TEXT          0x00070044 /* a string containing something with a grammar (conditions/responses?) */
#define K12_REC_START         0x00020030 /* a string containing human readable start time  */
#define K12_REC_STOP          0x00020031 /* a string containing human readable stop time */

/*
 * According to the Tektronix documentation, packets, i.e. "data events",
 * have several different group/type values, which differ in the last
 * nibble of the type code.  For now, we just mask that nibble off; the
 * format of the items are different, so we might have to treat different
 * data event types differently.
 */
#define K12_MASK_PACKET       0xfffffff0

/* offsets of elements in the records */
#define K12_RECORD_LEN         0x0 /* uint32, in bytes */
#define K12_RECORD_TYPE        0x4 /* uint32, see above */
#define K12_RECORD_FRAME_LEN   0x8 /* uint32, in bytes */
#define K12_RECORD_SRC_ID      0xc /* uint32 */

/*
 * Some records from K15 files have a port ID of an undeclared
 * interface which happens to be the only one with the first byte changed.
 * It is still unknown how to recognize when this happens.
 * If the lookup of the interface record fails we'll mask it
 * and retry.
 */
#define K12_RECORD_SRC_ID_MASK 0x00ffffff

/* elements of packet records */
#define K12_PACKET_TIMESTAMP  0x18 /* int64 (8b) representing 1/2us since 01-01-1990 Z00:00:00 */

#define K12_PACKET_FRAME      0x20 /* start of the actual frame in the record */
#define K12_PACKET_FRAME_D0020 0x34 /* start of the actual frame in the record */

#define K12_PACKET_OFFSET_VP  0x08 /* 2 bytes, big endian */
#define K12_PACKET_OFFSET_VC  0x0a /* 2 bytes, big endian */
#define K12_PACKET_OFFSET_CID 0x0c /* 1 byte */

/* elements of the source description records */
#define K12_SRCDESC_COLOR_FOREGROUND 0x12 /* 1 byte */
#define K12_SRCDESC_COLOR_BACKGROUND 0x13 /* 1 byte */

#define K12_SRCDESC_PORT_TYPE  0x1a /* 1 byte */
#define K12_SRCDESC_HWPARTLEN  0x1e /* uint16, big endian */
#define K12_SRCDESC_NAMELEN    0x20 /* uint16, big endian */
#define K12_SRCDESC_STACKLEN   0x22 /* uint16, big endian */

/* Hardware part of the record */
#define K12_SRCDESC_HWPART     0x24 /* offset of the hardware part */

/* Offsets relative to the beginning of the hardware part */
#define K12_SRCDESC_HWPARTTYPE 0    /* uint32, big endian */

#define K12_SRCDESC_DS0_MASK   24   /* variable-length */

#define K12_SRCDESC_ATM_VPI    20   /* uint16, big endian */
#define K12_SRCDESC_ATM_VCI    22   /* uint16, big endian */
#define K12_SRCDESC_ATM_AAL    24   /* 1 byte */

/*
 * A "stack file", as appears in a K12_REC_STK_FILE record, is a text
 * file (with CR-LF line endings) with a sequence of lines, each of
 * which begins with a keyword, and has white-space-separated tokens
 * after that.
 *
 * They appear to be:
 *
 *   STKVER, which is followed by a number (presumably a version number
 *   for the stack file format)
 *
 *   STACK, which is followed by a quoted string ("ProtocolStack" in one
 *   file) and two numbers
 *
 *   PATH, which is followed by a non-quoted string giving the pathname
 *   of the directory containing the stack file
 *
 *   HLAYER, which is followed by a quoted string, a path for something
 *   (protocol module?), a keyword ("LOADED", in one file), and a
 *   quoted string giving a description - this is probably a protocol
 *   layer of some sort
 *
 *   LAYER, which has a similar syntax to HLAYER - the first quoted
 *   string is a protocol name
 *
 *   RELATION, which has a quoted string giving a protocol name,
 *   another quoted string giving a protocol name, and a condition
 *   specifier of some sort, which probably says the second protocol
 *   is layered atop the first protocol if the condition is true.
 *   The first protocol can also be "BASE", which means that the
 *   second protocol is the lowest-level protocol.
 *   The conditions are:
 *
 *     CPLX, which may mean "complex" - it has parenthesized expressions
 *     including "&", presumably a boolean AND, with the individual
 *     tests being L:expr, where L is a letter such as "L", "D", or "P",
 *     and expr is:
 *
 *        0x........ for L, where each . is a hex digit or a ?, presumably
 *        meaning "don't care"
 *
 *        0;0{=,!=}0b........ for D, where . is presumably a bit or a ?
 *
 *        param=value for P, where param is something such as "src_port"
 *        and value is a value, presumably to test, for example, TCP or
 *        UDP ports
 *
 *     UNCOND, presumably meaning "always"
 *
 *     PARAM, followed by a parameter name (as with P:) and a value,
 *     possibly followed by LAYPARAM and a hex value
 *
 *   DECKRNL, followed by a quoted string protocol name, un-quoted
 *   "LSBF" or "MSBF" (Least/Most Significant Byte First?), and
 *   an un-quoted string ending with _DK
 *
 *   LAYPARAM, followed by a quoted protocol name and a number (-2147221504
 *   in one file, which is 0x80040000)
 *
 *   SPC_CONF, folloed by a number, a quoted string with numbers separated
 *   by hyphens, and another number
 *
 *   CIC_CONF, with a similar syntax to SPC_CONF
 *
 *   LAYPOS, followed by a protocol name or "BASE" and 3 numbers.
 *
 * Most of this is probably not useful, but the RELATION lines with
 * "BASE" could be used to figure out how to start the dissection
 * (if we knew what "L" and "D" did), and *some* of the others might
 * be useful if they don't match what's already in various dissector
 * tables (the ones for IP and a higher-level protocol, for example,
 * aren't very useful, as those are standardized, but the ones for
 * TCP, UDP, and SCTP ports, and SCTP PPIs, might be useful).
 */

/*
 * get_record: Get the next record into a buffer
 *   Every about 0x2000 bytes 0x10 bytes are inserted in the file,
 *   even in the middle of a record.
 *   This reads the next record without the eventual 0x10 bytes.
 *   returns the length of the record + the stuffing (if any)
 *
 *   Returns number of bytes read on success, 0 on EOF, -1 on error;
 *   if -1 is returned, *err is set to the error indication and, for
 *   errors where that's appropriate, *err_info is set to an additional
 *   error string.
 *
 * XXX: works at most with 0x1FFF bytes per record
 */
static gint get_record(k12_t *file_data, FILE_T fh, gint64 file_offset,
                       gboolean is_random, int *err, gchar **err_info) {
    guint8 *buffer = is_random ? file_data->rand_read_buff : file_data->seq_read_buff;
    guint buffer_len = is_random ? file_data->rand_read_buff_len : file_data->seq_read_buff_len;
    guint bytes_read;
    guint last_read;
    guint left;
    guint8 junk[0x14];
    guint8* writep;
#ifdef DEBUG_K12
    guint actual_len;
#endif

    /* where the next unknown 0x10 bytes are stuffed to the file */
    guint junky_offset = 0x2000 - (gint) ( (file_offset - 0x200) % 0x2000 );

    K12_DBG(6,("get_record: ENTER: junky_offset=%" G_GINT64_MODIFIER "d, file_offset=%" G_GINT64_MODIFIER "d",junky_offset,file_offset));

    /* no buffer is given, lets create it */
    if (buffer == NULL) {
        buffer = (guint8*)g_malloc(0x2000);
        buffer_len = 0x2000;
        if (is_random) {
            file_data->rand_read_buff = buffer;
            file_data->rand_read_buff_len = buffer_len;
        } else {
            file_data->seq_read_buff = buffer;
            file_data->seq_read_buff_len = buffer_len;
        }
    }

    /* Get the record length. */
    if ( junky_offset == 0x2000 ) {
        /* the length of the record is 0x10 bytes ahead from we are reading */
        bytes_read = file_read(junk,0x14,fh);

        if (bytes_read == 2 && junk[0] == 0xff && junk[1] == 0xff) {
            K12_DBG(1,("get_record: EOF"));
            return 0;
        } else if ( bytes_read < 0x14 ){
            K12_DBG(1,("get_record: SHORT READ OR ERROR"));
            *err = file_error(fh, err_info);
            if (*err == 0) {
                *err = WTAP_ERR_SHORT_READ;
            }
            return -1;
        }

        memcpy(buffer,&(junk[0x10]),4);
    } else {
        /* the length of the record is right where we are reading */
        bytes_read = file_read(buffer, 0x4, fh);

        if (bytes_read == 2 && buffer[0] == 0xff && buffer[1] == 0xff) {
            K12_DBG(1,("get_record: EOF"));
            return 0;
	} else if (bytes_read == 4 && buffer[0] == 0xff && buffer[1] == 0xff
	           && buffer[2] == 0x00 && buffer[3] == 0x00) {
            /*
             * In at least one k18 RF5 file, there appears to be a "record"
             * with a length value of 0xffff0000, followed by a bunch of
             * data that doesn't appear to be records, including a long
             * list of numbers.
             *
             * We treat a length value of 0xffff0000 as an end-of-file
             * indication.
             *
             * XXX - is this a length indication, or will it appear
             * at the beginning of an 8KB block, so that we should
             * check for it above?
             */
            K12_DBG(1,("get_record: EOF"));
            return 0;
        } else if ( bytes_read != 0x4 ) {
            K12_DBG(1,("get_record: SHORT READ OR ERROR"));
            *err = file_error(fh, err_info);
            if (*err == 0) {
                *err = WTAP_ERR_SHORT_READ;
            }
            return -1;
        }
    }

    left = pntoh32(buffer + K12_RECORD_LEN);
#ifdef DEBUG_K12
    actual_len = left;
#endif
    junky_offset -= 0x4;

    K12_DBG(5,("get_record: GET length=%u",left));

    /*
     * Record length must be at least large enough for the length,
     * hence 4 bytes.
     *
     * XXX - Is WTAP_MAX_PACKET_SIZE the right check for a maximum
     * record size?  Should we report this error differently?
     */
    if (left < 4 || left > WTAP_MAX_PACKET_SIZE) {
        K12_DBG(1,("get_record: Invalid GET length=%u",left));
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("get_record: Invalid GET length=%u",left);
        return -1;
    }

    /*
     * XXX - calculate the lowest power of 2 >= left, rather than just
     * looping.
     */
    while (left > buffer_len) {
    	buffer = (guint8*)g_realloc(buffer,buffer_len*=2);
        if (is_random) {
            file_data->rand_read_buff = buffer;
            file_data->rand_read_buff_len = buffer_len;
        } else {
            file_data->seq_read_buff = buffer;
            file_data->seq_read_buff_len = buffer_len;
        }
    }

    writep = buffer + 4;
    left -= 4;

    /* Read the rest of the record. */
    do {
        K12_DBG(6,("get_record: looping left=%d junky_offset=%" G_GINT64_MODIFIER "d",left,junky_offset));

        if (junky_offset > left) {
            bytes_read += last_read = file_read(writep, left, fh);

            if ( last_read != left ) {
                K12_DBG(1,("get_record: SHORT READ OR ERROR"));
                *err = file_error(fh, err_info);
                if (*err == 0) {
                    *err = WTAP_ERR_SHORT_READ;
                }
                return -1;
            } else {
                K12_HEX_ASCII_DUMP(5,file_offset, "GOT record", buffer, actual_len);
                return bytes_read;
            }
        } else {
            bytes_read += last_read = file_read(writep, junky_offset, fh);

            if ( last_read != junky_offset ) {
                K12_DBG(1,("get_record: SHORT READ OR ERROR, read=%d expected=%d",last_read, junky_offset));
                *err = file_error(fh, err_info);
                if (*err == 0) {
                    *err = WTAP_ERR_SHORT_READ;
                }
                return -1;
            }

            writep += last_read;

            bytes_read += last_read = file_read(junk, 0x10, fh);

            if ( last_read != 0x10 ) {
                K12_DBG(1,("get_record: SHORT READ OR ERROR"));
                *err = file_error(fh, err_info);
                if (*err == 0) {
                    *err = WTAP_ERR_SHORT_READ;
                }
                return -1;
            }

            left -= junky_offset;
            junky_offset = 0x2000;
        }

    } while(left);

    K12_HEX_ASCII_DUMP(5,file_offset, "GOT record", buffer, actual_len);
    return bytes_read;
}

static void
process_packet_data(struct wtap_pkthdr *phdr, Buffer *target, guint8 *buffer,
                    gint len, k12_t *k12)
{
    guint32 type;
    guint   buffer_offset;
    guint64 ts;
    guint32 length;
    guint32 extra_len;
    guint32 src_id;
    k12_src_desc_t* src_desc;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS;

    ts = pntoh64(buffer + K12_PACKET_TIMESTAMP);

    phdr->ts.secs = (guint32) ((ts / 2000000) + 631152000);
    phdr->ts.nsecs = (guint32) ( (ts % 2000000) * 500 );

    length = pntoh32(buffer + K12_RECORD_FRAME_LEN) & 0x00001FFF;
    phdr->len = phdr->caplen = length;

    type = pntoh32(buffer + K12_RECORD_TYPE);
    buffer_offset = (type == K12_REC_D0020) ? K12_PACKET_FRAME_D0020 : K12_PACKET_FRAME;

    buffer_assure_space(target, length);
    memcpy(buffer_start_ptr(target), buffer + buffer_offset, length);

    /* extra information need by some protocols */
    extra_len = len - buffer_offset - length;
    buffer_assure_space(&(k12->extra_info), extra_len);
    memcpy(buffer_start_ptr(&(k12->extra_info)),
           buffer + buffer_offset + length, extra_len);
    phdr->pseudo_header.k12.extra_info = (guint8*)buffer_start_ptr(&(k12->extra_info));
    phdr->pseudo_header.k12.extra_length = extra_len;

    src_id = pntoh32(buffer + K12_RECORD_SRC_ID);
    K12_DBG(5,("process_packet_data: src_id=%.8x",src_id));
    phdr->pseudo_header.k12.input = src_id;

    if ( ! (src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id))) ) {
        /*
         * Some records from K15 files have a port ID of an undeclared
         * interface which happens to be the only one with the first byte changed.
         * It is still unknown how to recognize when this happens.
         * If the lookup of the interface record fails we'll mask it
         * and retry.
         */
        src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id&K12_RECORD_SRC_ID_MASK));
    }

    if (src_desc) {
        K12_DBG(5,("process_packet_data: input_name='%s' stack_file='%s' type=%x",src_desc->input_name,src_desc->stack_file,src_desc->input_type));
        phdr->pseudo_header.k12.input_name = src_desc->input_name;
        phdr->pseudo_header.k12.stack_file = src_desc->stack_file;
        phdr->pseudo_header.k12.input_type = src_desc->input_type;

        switch(src_desc->input_type) {
            case K12_PORT_ATMPVC:
                if ((long)(buffer_offset + length + K12_PACKET_OFFSET_CID) < len) {
                    phdr->pseudo_header.k12.input_info.atm.vp =  pntoh16(buffer + buffer_offset + length + K12_PACKET_OFFSET_VP);
                    phdr->pseudo_header.k12.input_info.atm.vc =  pntoh16(buffer + buffer_offset + length + K12_PACKET_OFFSET_VC);
                    phdr->pseudo_header.k12.input_info.atm.cid =  *((unsigned char*)(buffer + buffer_offset + length + K12_PACKET_OFFSET_CID));
                    break;
                }
                /* Fall through */
            default:
                memcpy(&(phdr->pseudo_header.k12.input_info),&(src_desc->input_info),sizeof(src_desc->input_info));
                break;
        }
    } else {
        K12_DBG(5,("process_packet_data: NO SRC_RECORD FOUND"));

        memset(&(phdr->pseudo_header.k12),0,sizeof(phdr->pseudo_header.k12));
        phdr->pseudo_header.k12.input_name = "unknown port";
        phdr->pseudo_header.k12.stack_file = "unknown stack file";
    }

    phdr->pseudo_header.k12.input = src_id;
    phdr->pseudo_header.k12.stuff = k12;
}

static gboolean k12_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset) {
    k12_t *k12 = (k12_t *)wth->priv;
    k12_src_desc_t* src_desc;
    guint8* buffer;
    gint64 offset;
    gint len;
    guint32 type;
    guint32 src_id;

    offset = file_tell(wth->fh);

    /* ignore the record if it isn't a packet */
    do {
        K12_DBG(5,("k12_read: offset=%i",offset));

        *data_offset = offset;

        len = get_record(k12, wth->fh, offset, FALSE, err, err_info);

        if (len < 0) {
            /* read error */
            return FALSE;
        } else if (len == 0) {
            /* EOF */
            *err = 0;
            return FALSE;
        } else if (len < K12_RECORD_SRC_ID + 4) {
            /* Record not large enough to contain a src ID */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("data record length %d too short", len);
            return FALSE;
        }

        buffer = k12->seq_read_buff;

        type = pntoh32(buffer + K12_RECORD_TYPE);
        src_id = pntoh32(buffer + K12_RECORD_SRC_ID);


        if ( ! (src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id))) ) {
            /*
             * Some records from K15 files have a port ID of an undeclared
             * interface which happens to be the only one with the first byte changed.
             * It is still unknown how to recognize when this happens.
             * If the lookup of the interface record fails we'll mask it
             * and retry.
             */
            src_desc = (k12_src_desc_t*)g_hash_table_lookup(k12->src_by_id,GUINT_TO_POINTER(src_id&K12_RECORD_SRC_ID_MASK));
        }

        K12_DBG(5,("k12_read: record type=%x src_id=%x",type,src_id));

        offset += len;

    } while ( ((type & K12_MASK_PACKET) != K12_REC_PACKET && (type & K12_MASK_PACKET) != K12_REC_D0020) || !src_id || !src_desc );

    process_packet_data(&wth->phdr, wth->frame_buffer, buffer, len, k12);

    return TRUE;
}


static gboolean k12_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr, Buffer *buf, int *err, gchar **err_info) {
    k12_t *k12 = (k12_t *)wth->priv;
    guint8* buffer;
    gint len;

    K12_DBG(5,("k12_seek_read: ENTER"));

    if ( file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
        K12_DBG(5,("k12_seek_read: SEEK ERROR"));
        return FALSE;
    }

    len = get_record(k12, wth->random_fh, seek_off, TRUE, err, err_info);
    if (len < 0) {
        K12_DBG(5,("k12_seek_read: READ ERROR"));
        return FALSE;
    } else if (len < K12_RECORD_SRC_ID + 4) {
        /* Record not large enough to contain a src ID */
        K12_DBG(5,("k12_seek_read: SHORT READ"));
        *err = WTAP_ERR_SHORT_READ;
        return FALSE;
    }

    buffer = k12->rand_read_buff;

    process_packet_data(phdr, buf, buffer, len, k12);

    K12_DBG(5,("k12_seek_read: DONE OK"));

    return TRUE;
}


static k12_t* new_k12_file_data(void) {
    k12_t* fd = g_new(k12_t,1);

    fd->file_len = 0;
    fd->num_of_records = 0;
    fd->src_by_name = g_hash_table_new(g_str_hash,g_str_equal);
    fd->src_by_id = g_hash_table_new(g_direct_hash,g_direct_equal);
    fd->seq_read_buff = NULL;
    fd->seq_read_buff_len = 0;
    fd->rand_read_buff = NULL;
    fd->rand_read_buff_len = 0;

    buffer_init(&(fd->extra_info), 100);

    return fd;
}

static gboolean destroy_srcdsc(gpointer k _U_, gpointer v, gpointer p _U_) {
    k12_src_desc_t* rec = (k12_src_desc_t*)v;

    g_free(rec->input_name);
    g_free(rec->stack_file);
    g_free(rec);

    return TRUE;
}

static void destroy_k12_file_data(k12_t* fd) {
    g_hash_table_destroy(fd->src_by_id);
    g_hash_table_foreach_remove(fd->src_by_name,destroy_srcdsc,NULL);
    g_hash_table_destroy(fd->src_by_name);
    buffer_free(&(fd->extra_info));
    g_free(fd->seq_read_buff);
    g_free(fd->rand_read_buff);
    g_free(fd);
}

static void k12_close(wtap *wth) {
    k12_t *k12 = (k12_t *)wth->priv;

    destroy_k12_file_data(k12);
    wth->priv = NULL;	/* destroy_k12_file_data freed it */
#ifdef DEBUG_K12
    K12_DBG(5,("k12_close: CLOSED"));
    if (env_file) fclose(dbg_out);
#endif
}


int k12_open(wtap *wth, int *err, gchar **err_info) {
    k12_src_desc_t* rec;
    guint8 header_buffer[0x200];
    guint8* read_buffer;
    guint32 type;
    long offset;
    long len;
    guint port_type;
    guint32 rec_len;
    guint32 hwpart_len;
    guint32 name_len;
    guint32 stack_len;
    guint i;
    k12_t* file_data;

#ifdef DEBUG_K12
    gchar* env_level = getenv("K12_DEBUG_LEVEL");
    env_file = getenv("K12_DEBUG_FILENAME");
    if ( env_file ) {
	dbg_out = ws_fopen(env_file,"w");
	if (dbg_out == NULL) {
		dbg_out = stderr;
		K12_DBG(1,("unable to open K12 DEBUG FILENAME for writing!  Logging to standard error"));
	}
    }
    else
	dbg_out = stderr;
    if ( env_level ) debug_level = (unsigned int)strtoul(env_level,NULL,10);
    K12_DBG(1,("k12_open: ENTER debug_level=%u",debug_level));
#endif

    if ( file_read(header_buffer,0x200,wth->fh) != 0x200 ) {
        K12_DBG(1,("k12_open: FILE HEADER TOO SHORT OR READ ERROR"));
        *err = file_error(wth->fh, err_info);
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ) {
            return -1;
        }
        return 0;
    } else {
        if ( memcmp(header_buffer,k12_file_magic,8) != 0 ) {
            K12_DBG(1,("k12_open: BAD MAGIC"));
            return 0;
        }
    }

    offset = 0x200;

    file_data = new_k12_file_data();

    file_data->file_len = pntoh32( header_buffer + 0x8);
    file_data->num_of_records = pntoh32( header_buffer + 0xC );

    K12_DBG(5,("k12_open: FILE_HEADER OK: offset=%x file_len=%i records=%i",
            offset,
            file_data->file_len,
            file_data->num_of_records ));

    do {

        len = get_record(file_data, wth->fh, offset, FALSE, err, err_info);

        if ( len < 0 ) {
            K12_DBG(1,("k12_open: BAD HEADER RECORD",len));
            destroy_k12_file_data(file_data);
            return -1;
        }
        if (len == 0) {
            K12_DBG(1,("k12_open: BAD HEADER RECORD",len));
            *err = WTAP_ERR_SHORT_READ;
            destroy_k12_file_data(file_data);
            return -1;
        }

        if (len == 0) {
            K12_DBG(1,("k12_open: BAD HEADER RECORD",len));
            *err = WTAP_ERR_SHORT_READ;
            destroy_k12_file_data(file_data);
            return -1;
        }

        read_buffer = file_data->seq_read_buff;

        rec_len = pntoh32( read_buffer + K12_RECORD_LEN );
        if (rec_len < K12_RECORD_TYPE + 4) {
            /* Record isn't long enough to have a type field */
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("k12_open: record length %u < %u",
                                        rec_len, K12_RECORD_TYPE + 4);
            return -1;
        }
        type = pntoh32( read_buffer + K12_RECORD_TYPE );

        if ( (type & K12_MASK_PACKET) == K12_REC_PACKET ||
             (type & K12_MASK_PACKET) == K12_REC_D0020) {
            /*
             * we are at the first packet record, rewind and leave.
             */
            if (file_seek(wth->fh, offset, SEEK_SET, err) == -1) {
                destroy_k12_file_data(file_data);
                return -1;
            }
            K12_DBG(5,("k12_open: FIRST PACKET offset=%x",offset));
            break;
        } else if (type == K12_REC_SRCDSC || type == K12_REC_SRCDSC2 ) {
            rec = g_new0(k12_src_desc_t,1);

            if (rec_len < K12_SRCDESC_HWPART) {
                /*
                 * Record isn't long enough to have the fixed-length portion
                 * of the source descriptor field.
                 */
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("k12_open: source descriptor record length %u < %u",
                                            rec_len, K12_SRCDESC_HWPART);
                destroy_k12_file_data(file_data);
                g_free(rec);
                return -1;
            }
            port_type = read_buffer[K12_SRCDESC_PORT_TYPE];
            hwpart_len = pntoh16( read_buffer + K12_SRCDESC_HWPARTLEN );
            name_len = pntoh16( read_buffer + K12_SRCDESC_NAMELEN );
            stack_len = pntoh16( read_buffer + K12_SRCDESC_STACKLEN );

            rec->input = pntoh32( read_buffer + K12_RECORD_SRC_ID );

            K12_DBG(5,("k12_open: INTERFACE RECORD offset=%x interface=%x",offset,rec->input));

            if (name_len == 0) {
                K12_DBG(5,("k12_open: failed (name_len == 0 in source description"));
                destroy_k12_file_data(file_data);
                g_free(rec);
                return 0;
            }
            if (stack_len == 0) {
                K12_DBG(5,("k12_open: failed (stack_len == 0 in source description"));
                destroy_k12_file_data(file_data);
                g_free(rec);
                return 0;
            }
            if (rec_len < K12_SRCDESC_HWPART + hwpart_len + name_len + stack_len) {
                /*
                 * Record isn't long enough to have the full source descriptor
                 * field, including the variable-length parts.
                 */
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("k12_open: source descriptor record length %u < %u (%u + %u + %u + %u)",
                                            rec_len,
                                            K12_SRCDESC_HWPART + hwpart_len + name_len + stack_len,
                                            K12_SRCDESC_HWPART, hwpart_len, name_len, stack_len);
                destroy_k12_file_data(file_data);
                g_free(rec);
                return -1;
            }

            if (hwpart_len) {
                if (hwpart_len < 4) {
                    /* Hardware part isn't long enough to have a type field */
                    *err = WTAP_ERR_BAD_FILE;
                    *err_info = g_strdup_printf("k12_open: source descriptor hardware part length %u < 4",
                                                hwpart_len);
                    destroy_k12_file_data(file_data);
                    g_free(rec);
                    return -1;
                }
                switch(( rec->input_type = pntoh32( read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_HWPARTTYPE ) )) {
                    case K12_PORT_DS0S:
                        /* This appears to be variable-length */
                        rec->input_info.ds0mask = 0x00000000;
                        if (hwpart_len > K12_SRCDESC_DS0_MASK) {
                            for (i = 0; i < hwpart_len - K12_SRCDESC_DS0_MASK; i++) {
                                rec->input_info.ds0mask |= ( *(read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_DS0_MASK + i) == 0xff ) ? 0x1<<(31-i) : 0x0;
                            }
                        }
                        break;
                    case K12_PORT_ATMPVC:
                        if (hwpart_len < K12_SRCDESC_ATM_VCI + 2) {
                            /* Hardware part isn't long enough to have ATM information */
                            *err = WTAP_ERR_BAD_FILE;
                            *err_info = g_strdup_printf("k12_open: source descriptor hardware part length %u < %u",
                                                        hwpart_len,
                                                        K12_SRCDESC_ATM_VCI + 2);
                            destroy_k12_file_data(file_data);
                            g_free(rec);
                            return -1;
                        }

                        rec->input_info.atm.vp = pntoh16( read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_ATM_VPI );
                        rec->input_info.atm.vc = pntoh16( read_buffer + K12_SRCDESC_HWPART + K12_SRCDESC_ATM_VCI );
                        break;
                    default:
                        break;
                }
            } else {
                /* Record viewer generated files don't have this information */
                if (port_type >= 0x14
                    && port_type <= 0x17) {
                    /* For ATM2_E1DS1, ATM2_E3DS3,
                       ATM2_STM1EL and ATM2_STM1OP */
                    rec->input_type = K12_PORT_ATMPVC;
                    rec->input_info.atm.vp = 0;
                    rec->input_info.atm.vc = 0;
                }
            }

            if (read_buffer[K12_SRCDESC_HWPART + hwpart_len + name_len - 1] != '\0') {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("k12_open: source descriptor record contains non-null-terminated link-layer name");
                destroy_k12_file_data(file_data);
                g_free(rec);
                return -1;
            }
            if (read_buffer[K12_SRCDESC_HWPART + hwpart_len + name_len + stack_len - 1] != '\0') {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("k12_open: source descriptor record contains non-null-terminated stack path");
                destroy_k12_file_data(file_data);
                g_free(rec);
                return -1;
            }
            rec->input_name = (gchar *)g_memdup(read_buffer + K12_SRCDESC_HWPART + hwpart_len, name_len);
            rec->stack_file = (gchar *)g_memdup(read_buffer + K12_SRCDESC_HWPART + hwpart_len + name_len, stack_len);

            ascii_strdown_inplace (rec->stack_file);

            g_hash_table_insert(file_data->src_by_id,GUINT_TO_POINTER(rec->input),rec);
            g_hash_table_insert(file_data->src_by_name,rec->stack_file,rec);

            offset += len;
            continue;
        } else if (type == K12_REC_STK_FILE) {
            K12_DBG(1,("k12_open: K12_REC_STK_FILE"));
            K12_DBG(1,("Field 1: 0x%08x",pntoh32( read_buffer + 0x08 )));
            K12_DBG(1,("Field 2: 0x%08x",pntoh32( read_buffer + 0x0c )));
            K12_ASCII_DUMP(1, read_buffer, rec_len, 0x10);

            offset += len;
            continue;
        } else {
            K12_DBG(1,("k12_open: RECORD TYPE 0x%08x",type));
            offset += len;
            continue;
        }
    } while(1);

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_K12;
    wth->file_encap = WTAP_ENCAP_K12;
    wth->snapshot_length = 0;
    wth->subtype_read = k12_read;
    wth->subtype_seek_read = k12_seek_read;
    wth->subtype_close = k12_close;
    wth->priv = (void *)file_data;
    wth->tsprecision = WTAP_FILE_TSPREC_NSEC;

    return 1;
}

typedef struct {
	guint32 file_len;
	guint32 num_of_records;
	guint32 file_offset;
} k12_dump_t;

int k12_dump_can_write_encap(int encap) {

    if (encap == WTAP_ENCAP_PER_PACKET)
        return WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED;

    if (encap != WTAP_ENCAP_K12)
        return WTAP_ERR_UNSUPPORTED_ENCAP;

    return 0;
}

static const gchar dumpy_junk[] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

static gboolean k12_dump_record(wtap_dumper *wdh, guint32 len,  guint8* buffer, int *err_p) {
    k12_dump_t *k12 = (k12_dump_t *)wdh->priv;
    guint32 junky_offset = (0x2000 - ( (k12->file_offset - 0x200) % 0x2000 )) % 0x2000;

    if (len > junky_offset) {
        if (junky_offset) {
            if (! wtap_dump_file_write(wdh, buffer, junky_offset, err_p))
                return FALSE;
        }
        if (! wtap_dump_file_write(wdh, dumpy_junk, 0x10, err_p))
            return FALSE;

        if (! wtap_dump_file_write(wdh, buffer+junky_offset, len - junky_offset, err_p))
            return FALSE;

        k12->file_offset += len + 0x10;
    } else {
        if (! wtap_dump_file_write(wdh, buffer, len, err_p))
            return FALSE;
        k12->file_offset += len;
    }

    k12->num_of_records++;
    return TRUE;
}

static void k12_dump_src_setting(gpointer k _U_, gpointer v, gpointer p) {
    k12_src_desc_t* src_desc = (k12_src_desc_t*)v;
    wtap_dumper *wdh = (wtap_dumper *)p;
    guint32 len;
    guint offset;
    guint i;
    int   errxxx; /* dummy */

    union {
        guint8 buffer[0x2000];

        struct {
            guint32 len;
            guint32 type;
            guint32 unk32_1;
            guint32 input;

            guint16 unk32_2;
            guint16 color;
            guint32 unk32_3;
            guint32 unk32_4;
            guint16 unk16_1;
            guint16 hwpart_len;

            guint16 name_len;
            guint16 stack_len;

            struct {
                guint32 type;

                union {
                    struct {
                        guint32 unk32;
                        guint8 mask[32];
                    } ds0mask;

                    struct {
                        guint8 unk_data[0x10];
                        guint16 vp;
                        guint16 vc;
                    } atm;

                    guint32 unk;
                } desc;
            } extra;
        } record;
    } obj;

    obj.record.type = g_htonl(K12_REC_SRCDSC);
    obj.record.unk32_1 = g_htonl(0x00000001);
    obj.record.input = g_htonl(src_desc->input);

    obj.record.unk32_2 = g_htons(0x0000);
    obj.record.color = g_htons(0x060f);
    obj.record.unk32_3 = g_htonl(0x00000003);
    switch (src_desc->input_type) {
        case K12_PORT_ATMPVC:
            obj.record.unk32_4 = g_htonl(0x01001400);
            break;
        default:
            obj.record.unk32_4 = g_htonl(0x01000100);
    }

    obj.record.unk16_1 = g_htons(0x0000);
    obj.record.name_len = (guint16) strlen(src_desc->input_name) + 1;
    obj.record.stack_len = (guint16) strlen(src_desc->stack_file) + 1;

    obj.record.extra.type = g_htonl(src_desc->input_type);

    switch (src_desc->input_type) {
        case K12_PORT_ATMPVC:
            obj.record.hwpart_len = g_htons(0x18);
            obj.record.extra.desc.atm.vp = g_htons(src_desc->input_info.atm.vp);
            obj.record.extra.desc.atm.vc = g_htons(src_desc->input_info.atm.vc);
            offset = 0x3c;
            break;
        case K12_PORT_DS0S:
            obj.record.hwpart_len = g_htons(0x18);
            for( i=0; i<32; i++ ) {
                obj.record.extra.desc.ds0mask.mask[i] =
                (src_desc->input_info.ds0mask & (1 << i)) ? 0xff : 0x00;
            }
            offset = 0x3c;
            break;
        default:
            obj.record.hwpart_len = g_htons(0x08);
            offset = 0x2c;
            break;
    }

    memcpy(obj.buffer + offset,
           src_desc->input_name,
           obj.record.name_len);

    memcpy(obj.buffer + offset + obj.record.name_len,
           src_desc->stack_file,
           obj.record.stack_len);

    len = offset + obj.record.name_len + obj.record.stack_len;
    len += (len % 4) ? 4 - (len % 4) : 0;

    obj.record.len = g_htonl(len);
    obj.record.name_len =  g_htons(obj.record.name_len);
    obj.record.stack_len = g_htons(obj.record.stack_len);

    k12_dump_record(wdh,len,obj.buffer, &errxxx); /* fwrite errs ignored: see k12_dump below */
}

static gboolean k12_dump(wtap_dumper *wdh, const struct wtap_pkthdr *phdr,
                         const guint8 *pd, int *err) {
    const union wtap_pseudo_header *pseudo_header = &phdr->pseudo_header;
    k12_dump_t *k12 = (k12_dump_t *)wdh->priv;
    guint32 len;
    union {
        guint8 buffer[0x2000];
        struct {
            guint32 len;
            guint32 type;
            guint32 frame_len;
            guint32 input;

            guint32 datum_1;
            guint32 datum_2;
            guint64 ts;

            guint8 frame[0x1fc0];
        } record;
    } obj;

    /* We can only write packet records. */
    if (phdr->rec_type != REC_TYPE_PACKET) {
        *err = WTAP_ERR_REC_TYPE_UNSUPPORTED;
        return FALSE;
    }

    if (k12->num_of_records == 0) {
        k12_t* file_data = (k12_t*)pseudo_header->k12.stuff;
        /* XXX: We'll assume that any fwrite errors in k12_dump_src_setting will    */
        /*      repeat during the final k12_dump_record at the end of k12_dump      */
        /*      (and thus cause an error return from k12_dump).                     */
        /*      (I don't see a reasonably clean way to handle any fwrite errors     */
        /*       encountered in k12_dump_src_setting).                              */
        g_hash_table_foreach(file_data->src_by_id,k12_dump_src_setting,wdh);
    }
    obj.record.len = 0x20 + phdr->caplen;
    obj.record.len += (obj.record.len % 4) ? 4 - obj.record.len % 4 : 0;

    len = obj.record.len;

    obj.record.len = g_htonl(obj.record.len);

    obj.record.type = g_htonl(K12_REC_PACKET);
    obj.record.frame_len = g_htonl(phdr->caplen);
    obj.record.input = g_htonl(pseudo_header->k12.input);

    obj.record.ts = GUINT64_TO_BE((((guint64)phdr->ts.secs - 631152000) * 2000000) + (phdr->ts.nsecs / 1000 * 2));

    memcpy(obj.record.frame,pd,phdr->caplen);

    return k12_dump_record(wdh,len,obj.buffer, err);
}

static const guint8 k12_eof[] = {0xff,0xff};

static gboolean k12_dump_close(wtap_dumper *wdh, int *err) {
    k12_dump_t *k12 = (k12_dump_t *)wdh->priv;
    union {
        guint8 b[sizeof(guint32)];
        guint32 u;
    } d;

    if (! wtap_dump_file_write(wdh, k12_eof, 2, err))
        return FALSE;

    if (wtap_dump_file_seek(wdh, 8, SEEK_SET, err) == -1)
        return FALSE;

    d.u = g_htonl(k12->file_len);

    if (! wtap_dump_file_write(wdh, d.b, 4, err))
        return FALSE;

    d.u = g_htonl(k12->num_of_records);

    if (! wtap_dump_file_write(wdh, d.b, 4, err))
        return FALSE;

    return TRUE;
}


gboolean k12_dump_open(wtap_dumper *wdh, int *err) {
    k12_dump_t *k12;

    if ( ! wtap_dump_file_write(wdh, k12_file_magic, 8, err)) {
        return FALSE;
    }

    if (wtap_dump_file_seek(wdh, 0x200, SEEK_SET, err) == -1)
        return FALSE;

    wdh->subtype_write = k12_dump;
    wdh->subtype_close = k12_dump_close;

    k12 = (k12_dump_t *)g_malloc(sizeof(k12_dump_t));
    wdh->priv = (void *)k12;
    k12->file_len = 0x200;
    k12->num_of_records = 0;
    k12->file_offset  = 0x200;

    return TRUE;
}
