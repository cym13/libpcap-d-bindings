/*
 * Copyright (c) 2013, Petar Alilovic,
 * Faculty of Electrical Engineering and Computing, University of Zagreb
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

module libpcap.nflog;
extern (C):

/*
 * Structure of an NFLOG header and TLV parts, as described at
 * http://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html
 *
 * The NFLOG header is big-endian.
 *
 * The TLV length and type are in host byte order.  The value is either
 * big-endian or is an array of bytes in some externally-specified byte
 * order (text string, link-layer address, link-layer header, packet
 * data, etc.).
 */
struct nflog_hdr_t {
    ubyte    nflog_family;        /* address family */
    ubyte    nflog_version;        /* version */
    ushort   nflog_rid;        /* resource ID */
}

struct nflog_tlv_t {
    ushort   tlv_length;        /* tlv length */
    ushort   tlv_type;        /* tlv type */
    /* value follows this */
}

struct nflog_packet_hdr_t {
    ushort   hw_protocol;    /* hw protocol */
    ubyte    hook;        /* netfilter hook */
    ubyte    pad;        /* padding to 32 bits */
}

struct nflog_hwaddr_t {
    ushort   hw_addrlen;    /* address length */
    ushort   pad;        /* padding to 32-bit boundary */
    ubyte[8] hw_addr;    /* address, up to 8 bytes */
}

struct nflog_timestamp_t {
    ulong    sec;
    ulong    usec;
}

/*
 * TLV types.
 */
immutable NFULA_PACKET_HDR =           1;    /* nflog_packet_hdr_t */
immutable NFULA_MARK =                 2;    /* packet mark from skbuff */
immutable NFULA_TIMESTAMP =            3;    /* nflog_timestamp_t for skbuff's time stamp */
immutable NFULA_IFINDEX_INDEV =        4;    /* ifindex of device on which packet received (possibly bridge group) */
immutable NFULA_IFINDEX_OUTDEV =       5;    /* ifindex of device on which packet transmitted (possibly bridge group) */
immutable NFULA_IFINDEX_PHYSINDEV =    6;    /* ifindex of physical device on which packet received (not bridge group) */
immutable NFULA_IFINDEX_PHYSOUTDEV =   7;    /* ifindex of physical device on which packet transmitted (not bridge group) */
immutable NFULA_HWADDR =               8;    /* nflog_hwaddr_t for hardware address */
immutable NFULA_PAYLOAD =              9;    /* packet payload */
immutable NFULA_PREFIX =              10;    /* text string - null-terminated, count includes NUL */
immutable NFULA_UID =                 11;    /* UID owning socket on which packet was sent/received */
immutable NFULA_SEQ =                 12;    /* sequence number of packets on this NFLOG socket */
immutable NFULA_SEQ_GLOBAL =          13;    /* sequence number of pakets on all NFLOG sockets */
immutable NFULA_GID =                 14;    /* GID owning socket on which packet was sent/received */
immutable NFULA_HWTYPE =              15;    /* ARPHRD_ type of skbuff's device */
immutable NFULA_HWHEADER =            16;    /* skbuff's MAC-layer header */
immutable NFULA_HWLEN =               17;    /* length of skbuff's MAC-layer header */

