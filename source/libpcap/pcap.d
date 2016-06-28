/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by the Computer Systems
 *    Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

module libpcap.pcap;
extern (C):

/+
#if defined(WIN32)
  #include <pcap-stdinc.h>
#elif defined(MSDOS)
  #include <sys/types.h>
  #include <sys/socket.h>  /* uint, ubyte etc. */
#else /* UN*X */
  #include <sys/types.h>
  #include <sys/time.h>
#endif /* WIN32/MSDOS/UN*X */

#ifndef PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap/bpf.h>
#endif
+/

import libpcap.bpf;
import core.stdc.stdio;
alias void bpf_insn;

/*
 * Version number of the current version of the pcap file format.
 *
 * NOTE: this is *NOT* the version number of the libpcap library.
 * To fetch the version information for the version of libpcap
 * you're using, use pcap_lib_version().
 */
immutable PCAP_VERSION_MAJOR = 2;
immutable PCAP_VERSION_MINOR = 4;

immutable PCAP_ERRBUF_SIZE = 256;

/+
/*
 * Compatibility for systems that have a bpf.h that
 * predates the bpf aliass for 64-bit support.
 */
#if BPF_RELEASE - 0 < 199406
alias    int bpf_int32;
alias    uint uint;
#endif
+/

alias void pcap_t;
alias void pcap_dumper_t;
alias pcap_if pcap_if_t;
alias pcap_addr pcap_addr_t;

/*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 *
 * Do not change the layout of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure).
 *
 * Also, do not change the interpretation of any of the members of this
 * structure, in any way (this includes using values other than
 * LINKTYPE_ values, as defined in "savefile.c", in the "linktype"
 * field).
 *
 * Instead:
 *
 *    introduce a new structure for the new format, if the layout
 *    of the structure changed;
 *
 *    send mail to "tcpdump-workers@lists.tcpdump.org", requesting
 *    a new magic number for your new capture file format, and, when
 *    you get the new magic number, put it in "savefile.c";
 *
 *    use that magic number for save files with the changed file
 *    header;
 *
 *    make the code in "savefile.c" capable of reading files with
 *    the old file header as well as files with the new file header
 *    (using the magic number to determine the header format).
 *
 * Then supply the changes by forking the branch at
 *
 *    https://github.com/the-tcpdump-group/libpcap/issues
 *
 * and issuing a pull request, so that future versions of libpcap and
 * programs that use it (such as tcpdump) will be able to read your new
 * capture file format.
 */
struct pcap_file_header {
    uint magic;
    ushort version_major;
    ushort version_minor;
    int  thiszone;    /* gmt to local correction */
    uint sigfigs;    /* accuracy of timestamps */
    uint snaplen;    /* max length saved portion of each pkt */
    uint linktype;    /* data link type (LINKTYPE_*) */
}

/*
 * Macros for the value returned by pcap_datalink_ext().
 *
 * If LT_FCS_LENGTH_PRESENT(x) is true, the LT_FCS_LENGTH(x) macro
 * gives the FCS length of packets in the capture.
 */
auto LT_FCS_LENGTH_PRESENT(T)(T x) { return x & 0x04000000; }
auto LT_FCS_LENGTH(T)(T x)         { return ((x & 0xF0000000) >> 28) ; }
auto LT_FCS_DATALINK_EXT(T)(T x)   { return (((x & 0xF) << 28) | 0x04000000);}

enum pcap_direction_t {
       PCAP_D_INOUT = 0,
       PCAP_D_IN,
       PCAP_D_OUT
}

/*
 * Generic per-packet information, as supplied by libpcap.
 *
 * The time stamp can and should be a "struct timeval", regardless of
 * whether your system supports 32-bit tv_sec in "struct timeval",
 * 64-bit tv_sec in "struct timeval", or both if it supports both 32-bit
 * and 64-bit applications.  The on-disk format of savefiles uses 32-bit
 * tv_sec (and tv_usec); this structure is irrelevant to that.  32-bit
 * and 64-bit versions of libpcap, even if they're on the same platform,
 * should supply the appropriate version of "struct timeval", even if
 * that's not what the underlying packet capture mechanism supplies.
 */

struct timeval {
    uint tv_sec;
    uint tv_usec;
}

struct pcap_pkthdr {
    timeval ts;    /* time stamp */
    uint caplen;    /* length of portion present */
    uint len;    /* length this packet (off wire) */
}

/*
 * As returned by the pcap_stats()
 */
struct pcap_stat {
    uint ps_recv;        /* number of packets received */
    uint ps_drop;        /* number of packets dropped */
    uint ps_ifdrop;    /* drops by interface -- only supported on some platforms */
/+
#ifdef WIN32
    uint bs_capt;        /* number of packets that reach the application */
#endif /* WIN32 */
+/
}

/+
#ifdef MSDOS
/*
 * As returned by the pcap_stats_ex()
 */
struct pcap_stat_ex {
       ulong  rx_packets;        /* total packets received       */
       ulong  tx_packets;        /* total packets transmitted    */
       ulong  rx_bytes;          /* total bytes received         */
       ulong  tx_bytes;          /* total bytes transmitted      */
       ulong  rx_errors;         /* bad packets received         */
       ulong  tx_errors;         /* packet transmit problems     */
       ulong  rx_dropped;        /* no space in Rx buffers       */
       ulong  tx_dropped;        /* no space available for Tx    */
       ulong  multicast;         /* multicast packets received   */
       ulong  collisions;

       /* detailed rx_errors: */
       ulong  rx_length_errors;
       ulong  rx_over_errors;    /* receiver ring buff overflow  */
       ulong  rx_crc_errors;     /* recv'd pkt with crc error    */
       ulong  rx_frame_errors;   /* recv'd frame alignment error */
       ulong  rx_fifo_errors;    /* recv'r fifo overrun          */
       ulong  rx_missed_errors;  /* recv'r missed packet         */

       /* detailed tx_errors */
       ulong  tx_aborted_errors;
       ulong  tx_carrier_errors;
       ulong  tx_fifo_errors;
       ulong  tx_heartbeat_errors;
       ulong  tx_window_errors;
     }
#endif
+/

/*
 * Item in a list of interfaces.
 */
struct pcap_if {
    pcap_if *next;
    char *name;        /* name to hand to "pcap_open_live()" */
    char *description;    /* textual description of interface, or NULL */
    pcap_addr *addresses;
    uint flags;    /* PCAP_IF_ interface flags */
}

immutable PCAP_IF_LOOPBACK = 0x00000001;    /* interface is loopback */
immutable PCAP_IF_UP = 0x00000002;    /* interface is up */
immutable PCAP_IF_RUNNING = 0x00000004;    /* interface is running */

alias void sockaddr;

/*
 * Representation of an interface address.
 */
struct pcap_addr {
    pcap_addr *next;
    sockaddr *addr;        /* address */
    sockaddr *netmask;    /* netmask for that address */
    sockaddr *broadaddr;    /* broadcast address for that address */
    sockaddr *dstaddr;    /* P2P destination address for that address */
}

alias void function(ubyte*, const pcap_pkthdr*, const ubyte*) pcap_handler;

/*
 * Error codes for the pcap API.
 * These will all be negative, so you can check for the success or
 * failure of a call that returns these codes by checking for a
 * negative value.
 */
immutable PCAP_ERROR = -1;    /* generic error code */
immutable PCAP_ERROR_BREAK = -2;    /* loop terminated by pcap_breakloop */
immutable PCAP_ERROR_NOT_ACTIVATED = -3;    /* the capture needs to be activated */
immutable PCAP_ERROR_ACTIVATED = -4;    /* the operation can't be performed on already activated captures */
immutable PCAP_ERROR_NO_SUCH_DEVICE = -5;    /* no such device exists */
immutable PCAP_ERROR_RFMON_NOTSUP = -6;    /* this device doesn't support rfmon (monitor) mode */
immutable PCAP_ERROR_NOT_RFMON = -7;    /* operation supported only in monitor mode */
immutable PCAP_ERROR_PERM_DENIED = -8;    /* no permission to open the device */
immutable PCAP_ERROR_IFACE_NOT_UP = -9;    /* interface isn't up */
immutable PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10;    /* this device doesn't support setting the time stamp type */
immutable PCAP_ERROR_PROMISC_PERM_DENIED = -11;    /* you don't have permission to capture in promiscuous mode */
immutable PCAP_ERROR_TSTAMP_PRECISION_NOTSUP = -12;  /* the requested time stamp precision is not supported */

/*
 * Warning codes for the pcap API.
 * These will all be positive and non-zero, so they won't look like
 * errors.
 */
immutable PCAP_WARNING = 1;    /* generic warning code */
immutable PCAP_WARNING_PROMISC_NOTSUP = 2;    /* this device doesn't support promiscuous mode */
immutable PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3;    /* the requested time stamp type is not supported */

/*
 * Value to pass to pcap_compile() as the netmask if you don't know what
 * the netmask is.
 */
immutable PCAP_NETMASK_UNKNOWN = 0xffffffff;

char    *pcap_lookupdev(char *);
int    pcap_lookupnet(const char *, uint *, uint *, char *);

pcap_t    *pcap_create(const char *, char *);
int    pcap_set_snaplen(pcap_t *, int);
int    pcap_set_promisc(pcap_t *, int);
int    pcap_can_set_rfmon(pcap_t *);
int    pcap_set_rfmon(pcap_t *, int);
int    pcap_set_timeout(pcap_t *, int);
int    pcap_set_tstamp_type(pcap_t *, int);
int    pcap_set_immediate_mode(pcap_t *, int);
int    pcap_set_buffer_size(pcap_t *, int);
int    pcap_set_tstamp_precision(pcap_t *, int);
int    pcap_get_tstamp_precision(pcap_t *);
int    pcap_activate(pcap_t *);

int    pcap_list_tstamp_types(pcap_t *, int **);
void    pcap_free_tstamp_types(int *);
int    pcap_tstamp_type_name_to_val(const char *);
char *pcap_tstamp_type_val_to_name(int);
char *pcap_tstamp_type_val_to_description(int);

/*
 * Time stamp types.
 * Not all systems and interfaces will necessarily support all of these.
 *
 * A system that supports PCAP_TSTAMP_HOST is offering time stamps
 * provided by the host machine, rather than by the capture device,
 * but not committing to any characteristics of the time stamp;
 * it will not offer any of the PCAP_TSTAMP_HOST_ subtypes.
 *
 * PCAP_TSTAMP_HOST_LOWPREC is a time stamp, provided by the host machine,
 * that's low-precision but relatively cheap to fetch; it's normally done
 * using the system clock, so it's normally synchronized with times you'd
 * fetch from system calls.
 *
 * PCAP_TSTAMP_HOST_HIPREC is a time stamp, provided by the host machine,
 * that's high-precision; it might be more expensive to fetch.  It might
 * or might not be synchronized with the system clock, and might have
 * problems with time stamps for packets received on different CPUs,
 * depending on the platform.
 *
 * PCAP_TSTAMP_ADAPTER is a high-precision time stamp supplied by the
 * capture device; it's synchronized with the system clock.
 *
 * PCAP_TSTAMP_ADAPTER_UNSYNCED is a high-precision time stamp supplied by
 * the capture device; it's not synchronized with the system clock.
 *
 * Note that time stamps synchronized with the system clock can go
 * backwards, as the system clock can go backwards.  If a clock is
 * not in sync with the system clock, that could be because the
 * system clock isn't keeping accurate time, because the other
 * clock isn't keeping accurate time, or both.
 *
 * Note that host-provided time stamps generally correspond to the
 * time when the time-stamping code sees the packet; this could
 * be some unknown amount of time after the first or last bit of
 * the packet is received by the network adapter, due to batching
 * of interrupts for packet arrival, queueing delays, etc..
 */
immutable PCAP_TSTAMP_HOST = 0;    /* host-provided, unknown characteristics */
immutable PCAP_TSTAMP_HOST_LOWPREC = 1;    /* host-provided, low precision */
immutable PCAP_TSTAMP_HOST_HIPREC = 2;    /* host-provided, high precision */
immutable PCAP_TSTAMP_ADAPTER = 3;    /* device-provided, synced with the system clock */
immutable PCAP_TSTAMP_ADAPTER_UNSYNCED = 4;    /* device-provided, not synced with the system clock */

/*
 * Time stamp resolution types.
 * Not all systems and interfaces will necessarily support all of these
 * resolutions when doing live captures; all of them can be requested
 * when reading a savefile.
 */
immutable PCAP_TSTAMP_PRECISION_MICRO = 0;    /* use timestamps with microsecond precision, default */
immutable PCAP_TSTAMP_PRECISION_NANO = 1;    /* use timestamps with nanosecond precision */

pcap_t    *pcap_open_live(const char *, int, int, int, char *);
pcap_t    *pcap_open_dead(int, int);
pcap_t    *pcap_open_dead_with_tstamp_precision(int, int, uint);
pcap_t    *pcap_open_offline_with_tstamp_precision(const char *, uint, char *);
pcap_t    *pcap_open_offline(const char *, char *);
/+
#if defined(WIN32)
pcap_t  *pcap_hopen_offline_with_tstamp_precision(intptr_t, uint, char *);
pcap_t  *pcap_hopen_offline(intptr_t, char *);
#if !defined(LIBPCAP_EXPORTS)
#define pcap_fopen_offline_with_tstamp_precision(f,p,b) \
    pcap_hopen_offline_with_tstamp_precision(_get_osfhandle(_fileno(f)), p, b)
#define pcap_fopen_offline(f,b) \
    pcap_hopen_offline(_get_osfhandle(_fileno(f)), b)
#else /*LIBPCAP_EXPORTS*/
static pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *, uint, char *);
static pcap_t *pcap_fopen_offline(FILE *, char *);
#endif
#else /*WIN32*/
pcap_t    *pcap_fopen_offline_with_tstamp_precision(FILE *, uint, char *);
pcap_t    *pcap_fopen_offline(FILE *, char *);
#endif /*WIN32*/
+/

void    pcap_close(pcap_t *);
int    pcap_loop(pcap_t *, int, pcap_handler, ubyte *);
int    pcap_dispatch(pcap_t *, int, pcap_handler, ubyte *);
ubyte* pcap_next(pcap_t *, pcap_pkthdr *);
int     pcap_next_ex(pcap_t *, pcap_pkthdr **, const ubyte **);
void    pcap_breakloop(pcap_t *);
int    pcap_stats(pcap_t *, pcap_stat *);
int    pcap_setfilter(pcap_t *, bpf_program *);
int     pcap_setdirection(pcap_t *, pcap_direction_t);
int    pcap_getnonblock(pcap_t *, char *);
int    pcap_setnonblock(pcap_t *, int, char *);
int    pcap_inject(pcap_t *, const void *, size_t);
int    pcap_sendpacket(pcap_t *, const ubyte *, int);
char *pcap_statustostr(int);
char *pcap_strerror(int);
char    *pcap_geterr(pcap_t *);
void    pcap_perror(pcap_t *, char *);
int    pcap_compile(pcap_t *, bpf_program *, const char *, int,
        uint);
int    pcap_compile_nopcap(int, int, bpf_program *,
        const char *, int, uint);
void    pcap_freecode(bpf_program *);
int    pcap_offline_filter(const bpf_program *,
        const pcap_pkthdr *, const ubyte *);
int    pcap_datalink(pcap_t *);
int    pcap_datalink_ext(pcap_t *);
int    pcap_list_datalinks(pcap_t *, int **);
int    pcap_set_datalink(pcap_t *, int);
void    pcap_free_datalinks(int *);
int    pcap_datalink_name_to_val(const char *);
char *pcap_datalink_val_to_name(int);
char *pcap_datalink_val_to_description(int);
int    pcap_snapshot(pcap_t *);
int    pcap_is_swapped(pcap_t *);
int    pcap_major_version(pcap_t *);
int    pcap_minor_version(pcap_t *);

/* XXX */
FILE    *pcap_file(pcap_t *);
int    pcap_fileno(pcap_t *);

pcap_dumper_t *pcap_dump_open(pcap_t *, const char *);
pcap_dumper_t *pcap_dump_fopen(pcap_t *, FILE *fp);
pcap_dumper_t *pcap_dump_open_append(pcap_t *, const char *);
FILE    *pcap_dump_file(pcap_dumper_t *);
long    pcap_dump_ftell(pcap_dumper_t *);
int    pcap_dump_flush(pcap_dumper_t *);
void    pcap_dump_close(pcap_dumper_t *);
void    pcap_dump(ubyte *, const pcap_pkthdr *, const ubyte *);

int    pcap_findalldevs(pcap_if_t **, char *);
void    pcap_freealldevs(pcap_if_t *);

char *pcap_lib_version();

/*
 * On at least some versions of NetBSD and QNX, we don't want to declare
 * bpf_filter() here, as it's also be declared in <net/bpf.h>, with a
 * different signature, but, on other BSD-flavored UN*Xes, it's not
 * declared in <net/bpf.h>, so we *do* want to declare it here, so it's
 * declared when we build pcap-bpf.c.
 */
/+
#if !defined(__NetBSD__) && !defined(__QNX__)
uint    bpf_filter(const bpf_insn *, const ubyte *, uint, uint);
#endif
+/
int    bpf_validate(const bpf_insn *f, int len);
char    *bpf_image(const bpf_insn *, int);
void    bpf_dump(const bpf_program *, int);

/+
#if defined(WIN32)

/*
 * Win32 definitions
 */

int pcap_setbuff(pcap_t *p, int dim);
int pcap_setmode(pcap_t *p, int mode);
int pcap_setmintocopy(pcap_t *p, int size);
Adapter *pcap_get_adapter(pcap_t *p);

#ifdef WPCAP
/* Include file with the wpcap-specific extensions */
#include <Win32-Extensions.h>
#endif /* WPCAP */

immutable MODE_CAPT = 0;
immutable MODE_STAT = 1;
immutable MODE_MON = 2;

#elif defined(MSDOS)

/*
 * MS-DOS definitions
 */

int  pcap_stats_ex (pcap_t *, pcap_stat_ex *);
void pcap_set_wait (pcap_t *p, void (*yield)(void), int wait);
ulong pcap_mac_packets (void);

#else /* UN*X */

/*
 * UN*X definitions
 */

int    pcap_get_selectable_fd(pcap_t *);

#endif /* WIN32/MSDOS/UN*X */
+/
