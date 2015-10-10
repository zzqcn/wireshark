

#include "config.h"
#include <glib.h>
#include <epan/packet.h>



#ifndef __DPI_PARSE_H__
#define __DPI_PARSE_H__


///////////   Ethernet  /////////////////////////////////////////////

#define ETHER_ADDR_LEN  6
#define ETHER_TYPE_LEN  2
#define ETHER_CRC_LEN   4
#define ETHER_HDR_LEN  (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN)
#define ETHER_MIN_LEN   64      /**< Min frame len, including CRC. */
#define ETHER_MAX_LEN   1518    /**< Max frame len, including CRC. */
#define ETHER_MIN_MTU   68      /**< Min MTU for IPv4 packets, see RFC 791 */
#define ETHER_MTU (ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN)

/** Max VLAN frame len, including CRC. */
#define ETHER_MAX_VLAN_FRAME_LEN    (ETHER_MAX_LEN + 4)
/** Max Jumbo frame len, including CRC. */
#define ETHER_MAX_JUMBO_FRAME_LEN   0x3F00
#define ETHER_MAX_VLAN_ID   4095    /**< Max VLAN ID. */


typedef struct dpi_ether_addr
{
    guint8 addr_bytes[ETHER_ADDR_LEN];
} dpi_ether_addr_t;

typedef struct dpi_ether_hdr
{
    dpi_ether_addr_t  dst;
    dpi_ether_addr_t  src;
    guint16 type;
} dpi_ether_hdr_t;


typedef struct dpi_vlan_hdr
{
    guint16 vlan_tci;    /**< Priority (3) + CFI (1) + Identifier Code (12) */
    guint16 eth_proto;   /**< Ethernet type of encapsulated frame. */
} dpi_vlan_hdr_t;



///////////  GRE ////////////////////////////////////

/*

The GRE packet header[1] has the following format:

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |C|       Reserved0       | Ver |         Protocol Type         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Checksum (optional)      |       Reserved1 (Optional)    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The proposed GRE header will have the following format:

    Ver值为 0-GRE， 1-Enhanced GRE
    Protocol Type为RFC 1700中定义的ETHER TYPES。当GRE载荷为ipv4时，此字段
        必须为0x0800

    bit C = 1时， Checksum、Reserved1出现
    bit K = 1时， Key出现
    bit S = 1时， Sequence Number出现

    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |C| |K|S| Reserved0       | Ver |         Protocol Type         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Checksum (optional)      |       Reserved1 (Optional)    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Key (optional)                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Sequence Number (Optional)                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */


#define GRE_HDR_MIN_LEN    4

#define GRE_CHECKSUM            0x8000
#define GRE_ROUTING             0x4000
#define GRE_KEY                 0x2000
#define GRE_SEQUENCE            0x1000


typedef struct dpi_gre_hdr
{
    guint16  flags_ver;  /**< 标志与版本 */
    guint16  type;       /**< 上层协议类型 */
} dpi_gre_hdr_t;


//////////// IPv4, IPv6 ////////////////////////////////

#define  IPv4_HDR_MIN_LEN   20
#define  IPv6_HDR_MIN_LEN   40


typedef union
{
    guint32  all[4];
    guint32  ipv4;       /**< ipv4地址 */
    guint32  ipv6[4];    /**< ipv6地址 */
} dpi_ip_addr;


typedef struct dpi_ipv4_hdr
{
    guint8   v_hl;
    guint8   tos;
    guint16  len;
    guint16  id;
    guint16  off;
    guint8   ttl;
    guint8   proto;
    guint16  sum;
    guint32  src;
    guint32  dst;
} dpi_ipv4_hdr_t;


typedef struct dpi_ipv6_hdr
{
    guint32 vtc_flow;     /**< IP version, traffic class & flow label. */
    guint16 tlen;  /**< IP packet length - includes sizeof(ip_header). */
    guint8  proto;        /**< Protocol, next header. */
    guint8  hop_limits;   /**< Hop limits. */
    guint8  src[16]; /**< IP address of source host. */
    guint8  dst[16]; /**< IP address of destination host(s). */
} dpi_ipv6_hdr_t;

/** Create IPv4 address */
#define IPv4(a,b,c,d) ((uint32_t)(((a) & 0xff) << 24) | \
                       (((b) & 0xff) << 16) | \
                       (((c) & 0xff) << 8)  | \
                       ((d) & 0xff))

/* Fragment Offset * Flags. */
#define	IPV4_HDR_DF_SHIFT	14
#define	IPV4_HDR_MF_SHIFT	13
#define	IPV4_HDR_FO_SHIFT	3

#define	IPV4_HDR_DF_FLAG	(1 << IPV4_HDR_DF_SHIFT)
#define	IPV4_HDR_MF_FLAG	(1 << IPV4_HDR_MF_SHIFT)

#define	IPV4_HDR_OFFSET_MASK	((1 << IPV4_HDR_MF_SHIFT) - 1)

#define	IPV4_HDR_OFFSET_UNITS	8


/*
 * IPv4 address types
 */
#define IPV4_ANY              ((uint32_t)0x00000000) /**< 0.0.0.0 */
#define IPV4_LOOPBACK         ((uint32_t)0x7f000001) /**< 127.0.0.1 */
#define IPV4_BROADCAST        ((uint32_t)0xe0000000) /**< 224.0.0.0 */
#define IPV4_ALLHOSTS_GROUP   ((uint32_t)0xe0000001) /**< 224.0.0.1 */
#define IPV4_ALLRTRS_GROUP    ((uint32_t)0xe0000002) /**< 224.0.0.2 */
#define IPV4_MAX_LOCAL_GROUP  ((uint32_t)0xe00000ff) /**< 224.0.0.255 */

/*
 * IPv4 Multicast-related macros
 */
#define IPV4_MIN_MCAST  IPv4(224, 0, 0, 0)          /**< Minimal IPv4-multicast address */
#define IPV4_MAX_MCAST  IPv4(239, 255, 255, 255)    /**< Maximum IPv4 multicast address */

#define IS_IPV4_MCAST(x) \
    ((x) >= IPV4_MIN_MCAST && (x) <= IPV4_MAX_MCAST) /**< check if IPv4 address is multicast */


////////////// TCP ///////////////////////

#define TCP_HDR_MIN_LEN     20


typedef struct dpi_tcp_hdr
{
    guint16 src;   /**< TCP source port. */
    guint16 dst;   /**< TCP destination port. */
    guint32 seq;   /**< TX data sequence number. */
    guint32 ack;   /**< RX data acknowledgement sequence number. */
    guint8  off;   /**< Data offset. */
    guint8  flags; /**< TCP flags */
    guint16 win;   /**< RX flow control window. */
    guint16 sum;   /**< TCP checksum. */
    guint16 urp;   /**< TCP urgent pointer, if any. */
} dpi_tcp_hdr_t;


/////////////  UDP  /////////////////////////

#define UDP_HDR_LEN     8

typedef struct dpi_udp_hdr
{
    guint16 src;  /**< UDP source port. */
    guint16 dst;  /**< UDP destination port. */
    guint16 len;  /**< UDP datagram length */
    guint16 sum;  /**< UDP datagram checksum */
} dpi_udp_hdr_t;


//////////////////////////////////////////////////////////////////////


typedef struct dpi_packet
{
    gint16  lnk_type;    /**< ethernet etc */
    gint16  net_type;    /**< ipv4, ipv6 etc */
    gint16  tran_type;   /**< TCP, UDP etc */
    dpi_ether_hdr_t*    eth_hdr;
    dpi_ipv4_hdr_t*     ipv4_hdr;
    dpi_ipv6_hdr_t*     ipv6_hdr;
    dpi_tcp_hdr_t*      tcp_hdr;
    dpi_udp_hdr_t*      udp_hdr;
    guint8* payload;     /**< TCP, UDP payload */
    gint16  payload_offset;
    gint16  payload_len; /**< payload length */
} dpi_packet_t;



int get_dpi_packet_info(tvbuff_t* tvb, packet_info* pinfo, dpi_packet_t* pkt);




#endif /* __DPI_PARSE_H__ */

