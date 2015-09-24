
#include "config.h"

#include <epan/packet.h>
#include <epan/tvbuff-int.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <wiretap/wtap.h>

#include "parse.h"

int get_dpi_packet_info(tvbuff_t* tvb, packet_info* pinfo, dpi_packet_t* pkt)
{
    //int ret = 0;
    gint ip_len, tran_len, offset;
    gint eth_t, ip_t;
    guint8* frame = NULL;
    guint frame_len = 0;


    if(NULL == tvb || NULL == pinfo || NULL == pkt)
        return -1;

    frame = (guint8*)tvb->real_data;
    frame_len = tvb_captured_length(tvb);

    offset = 0;
    ip_len = tran_len = 0;

    if(pinfo->fd->lnk_t != WTAP_ENCAP_ETHERNET)
        return -1; // TODO: support ethernet only
    if(frame_len < (ETHER_HDR_LEN + 1))
        return -1;
    
    pkt->lnk_type = WTAP_ENCAP_ETHERNET;
    pkt->eth_hdr = frame + offset;
    
    eth_t = tvb_get_ntohs(tvb, offset + 2*ETHER_ADDR_LEN);
    if(eth_t != ETHERTYPE_IP && eth_t != ETHERTYPE_IPv6)
        return -1; // TODO: support ipv4 /ipv6 only
    offset += ETHER_HDR_LEN;
    

    pkt->net_type = eth_t;
    ip_t = -1;
    if(eth_t == ETHERTYPE_IP)
    {
ipv4:
        ip_len = (tvb_get_guint8(tvb, offset) & 0x0f) << 2;
        ip_t = tvb_get_guint8(tvb, offset + 9);
        pkt->net_type = ETHERTYPE_IP;
        pkt->ipv4_hdr = frame + offset;
    }
    else if(eth_t == ETHERTYPE_IPv6)
    {
ipv6:
        ip_len = IPv6_HDR_MIN_LEN;
        ip_t = tvb_get_guint8(tvb, offset + 6);
        pkt->net_type = ETHERTYPE_IPv6;
        pkt->ipv6_hdr = frame + offset;
    }
    offset += ip_len;

    if(ip_t == IP_PROTO_TCP)
    {
        tran_len = (tvb_get_guint8(tvb, offset + 12) >> 4) << 2;
        pkt->tran_type = IP_PROTO_TCP;
        pkt->tcp_hdr = frame + offset;
    }
    else if(ip_t == IP_PROTO_UDP)
    {
        tran_len = UDP_HDR_LEN;
        pkt->tran_type = IP_PROTO_UDP;
        pkt->udp_hdr = frame + offset;
    }
    else if(ip_t == IP_PROTO_GRE)
    {
        guint16 flags_ver, gre_type;
        guint8 gre_len = GRE_HDR_MIN_LEN;

        flags_ver = tvb_get_ntohs(tvb, offset);
        gre_type = tvb_get_ntohs(tvb, offset + 2);
        if(flags_ver & GRE_CHECKSUM || flags_ver & GRE_ROUTING)
            gre_len += 4;
        if(flags_ver & GRE_ROUTING)
            gre_len += 4;
        if(flags_ver & GRE_KEY)
            gre_len += 4;
        if(flags_ver & GRE_SEQUENCE)
            gre_len += 4;
        
        pkt->tran_type = IP_PROTO_GRE;
        offset += gre_len;

        if(gre_type == ETHERTYPE_IP)
            goto ipv4;
        else if(gre_type == ETHERTYPE_IPv6)
            goto ipv6;
        else
            return -1;
    }
    else
        return -1;
    offset += tran_len;

    pkt->payload = frame + offset;
    pkt->payload_offset = offset;
    pkt->payload_len = tvb_captured_length_remaining(tvb, offset);

    return 0;
}

