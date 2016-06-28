/*
 * Copyright (c) 2006 Paolo Abeni (Italy)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Basic USB data struct
 * By Paolo Abeni <paolo.abeni@email.it>
 */

extern (C):

/*
 * possible transfer mode
 */
immutable URB_TRANSFER_IN = 0x80;
immutable URB_ISOCHRONOUS = 0x0;
immutable URB_INTERRUPT = 0x1;
immutable URB_CONTROL = 0x2;
immutable URB_BULK = 0x3;

/*
 * possible event type
 */
immutable URB_SUBMIT = 'S';
immutable URB_COMPLETE = 'C';
immutable URB_ERROR = 'E';

/*
 * USB setup header as defined in USB specification.
 * Appears at the front of each Control S-type packet in DLT_USB captures.
 */
struct pcap_usb_setup {
    ubyte    bmRequestType;
    ubyte    bRequest;
    ushort    wValue;
    ushort    wIndex;
    ushort    wLength;
}

/*
 * Information from the URB for Isochronous transfers.
 */
struct iso_rec {
    int    error_count;
    int    numdesc;
}

/*
 * Header prepended by linux kernel to each event.
 * Appears at the front of each packet in DLT_USB_LINUX captures.
 */
struct pcap_usb_header {
    ulong    id;
    ubyte    event_type;
    ubyte    transfer_type;
    ubyte    endpoint_number;
    ubyte    device_address;
    ushort    bus_id;
    char setup_flag;/*if !=0 the urb setup header is not present*/
    char data_flag; /*if !=0 no urb data is present*/
    long    ts_sec;
    int    ts_usec;
    int    status;
    uint    urb_len;
    uint    data_len; /* amount of urb data really present in this event*/
    pcap_usb_setup setup;
}

/*
 * Header prepended by linux kernel to each event for the 2.6.31
 * and later kernels; for the 2.6.21 through 2.6.30 kernels, the
 * "iso_rec" information, and the fields starting with "interval"
 * are zeroed-out padding fields.
 *
 * Appears at the front of each packet in DLT_USB_LINUX_MMAPPED captures.
 */
struct pcap_usb_header_mmapped {
    ulong    id;
    ubyte    event_type;
    ubyte    transfer_type;
    ubyte    endpoint_number;
    ubyte    device_address;
    ushort    bus_id;
    char setup_flag;/*if !=0 the urb setup header is not present*/
    char data_flag; /*if !=0 no urb data is present*/
    long    ts_sec;
    int    ts_usec;
    int    status;
    uint    urb_len;
    uint    data_len; /* amount of urb data really present in this event*/
    union s {
        pcap_usb_setup setup;
        iso_rec iso;
    };
    int    interval;    /* for Interrupt and Isochronous events */
    int    start_frame;    /* for Isochronous events */
    uint    xfer_flags;    /* copy of URB's transfer flags */
    uint    ndesc;    /* number of isochronous descriptors */
}

/*
 * Isochronous descriptors; for isochronous transfers there might be
 * one or more of these at the beginning of the packet data.  The
 * number of descriptors is given by the "ndesc" field in the header;
 * as indicated, in older kernels that don't put the descriptors at
 * the beginning of the packet, that field is zeroed out, so that field
 * can be trusted even in captures from older kernels.
 */
struct usb_isodesc {
    int        status;
    uint    offset;
    uint    len;
    ubyte[4]    pad;
}
