/**  toxrtp.h
 *
 *   Rtp implementation includes rtp_session_s struct which is a session identifier.
 *   It contains session information and it's a must for every session.
 *
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifndef _RTP__IMPL_H_
#define _RTP__IMPL_H_

#define RTP_VERSION 2
#include <inttypes.h>
#include "tox.h"

/* Extension header flags */
#define RTP_EXT_TYPE_RESOLUTION 0x01
#define RTP_EXT_TYPE_FRAMERATE  0x02

#define _PAYLOAD_OPUS 96 /* Audio */
#define _PAYLOAD_VP8 106 /* Video */


/**
 * Standard rtp header
 */

typedef struct rtp_header_s {
    uint8_t      _flags;             /* Version(2),Padding(1), Ext(1), Cc(4) */
    uint8_t      _marker_payloadt;   /* Marker(1), PlayLoad Type(7) */
    uint16_t     _sequence_number;   /* Sequence Number */
    uint32_t     _timestamp;         /* Timestamp */
    uint32_t     _ssrc;              /* SSRC */
    uint32_t*    _csrc;              /* CSRC's table */

    uint32_t     _length;

} rtp_header_t;

/**
 * Standard rtp extension header
 */

typedef struct rtp_ext_header_s {
    uint16_t     _ext_type;          /* Extension profile */
    uint16_t     _ext_len;           /* Number of extensions */
    uint32_t*    _hd_ext;            /* Extension's table */


} rtp_ext_header_t;

/**
 * Standard rtp message
 */

typedef struct rtp_msg_s {
    struct rtp_header_s*     _header;
    struct rtp_ext_header_s* _ext_header;
    uint32_t                 _header_lenght;

    uint8_t*                 _data;
    uint32_t                 _length;
    tox_IP_Port              _from;

    struct rtp_msg_s*        _next;
} rtp_msg_t;

/**
 * Our main session descriptor.
 * It measures the session variables and controls
 * the entire session. There are functions for manipulating
 * the session so tend to use those instead of directly modifying
 * session parameters.
 */

typedef struct rtp_session_s {
    uint8_t                 _version;
    uint8_t                 _padding;
    uint8_t                 _extension;
    uint8_t                 _cc;
    uint8_t                 _marker;
    uint8_t                 _payload_type;
    uint16_t                _sequence_number;        /* Set when sending */
    uint16_t                _remote_sequence_number; /* Check when recving msg */
    uint32_t                _current_timestamp;
    uint32_t                _ssrc;
    uint32_t*               _csrc;

    /* If some additional data must be sent via message
     * apply it here. Only by allocating this member you will be
     * automatically placing it within a message.
     */

    tox_IP_Port                 _dest;

    struct rtp_ext_header_s*    _ext_header;
    /* External header identifiers */
    int                         _exthdr_resolution;
    int                         _exthdr_framerate;


    /* Since these are only references of the
     * call structure don't allocate or free
     */

    uint8_t*                    _encrypt_key;
    uint8_t*                    _decrypt_key;

    uint8_t*                    _encrypt_nonce;
    uint8_t*                    _decrypt_nonce;

    /**************************************/

    struct rtp_msg_s*           _oldest_msg;
    struct rtp_msg_s*           _last_msg; /* tail */

    uint8_t                     _prefix; /* Msg prefix for core to know when recving */

    pthread_mutex_t             _mutex;

} rtp_session_t;


void
rtp_free_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg );

/**
 * Release all messages held by session
 */
int
rtp_release_session_recv ( rtp_session_t* _session );

/**
 * Functions handling receiving
 */
struct rtp_msg_s*
rtp_recv_msg ( rtp_session_t* _session );

/**
 * rtp_msg_parse() stores headers separately from the payload data
 * and so the _length variable is set accordingly. _sequnum argument is
 * passed by the rtp_handlepacket function since it's parsed already
 */
struct rtp_msg_s*
rtp_msg_parse ( rtp_session_t* _session, uint16_t _sequnum, const uint8_t* _data, uint32_t _length );



int
rtp_send_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg, void* _core_handler );

/**
 * rtp_msg_new() stores headers and payload data in one container ( _data )
 * and the _length is set accordingly. Returned message is used for sending only
 * so there is not much use of the headers there
 */
struct rtp_msg_s*
rtp_msg_new ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length );

/**
 * Callback that is called from cores networking poll.
 */
int
rtp_handlepacket ( void* _object, tox_IP_Port ip_port, uint8_t* data, uint32_t length );

/**
 * Session initialization and termination.
 */
rtp_session_t*
rtp_init_session ( void* net_core, int payload_type );

int
rtp_terminate_session ( rtp_session_t* _session );



/**
 * FUNCTIONS BELOW ARE DEPRECATED AND WILL BE REMOVED IN LATER COMMITS
 */

/* Convenient functions for marking the resolution */
int                     rtp_add_resolution_marking ( rtp_session_t* _session, uint16_t _width, uint16_t _height );
int                     rtp_remove_resolution_marking ( rtp_session_t* _session );
uint16_t                rtp_get_resolution_marking_height ( struct rtp_ext_header_s* _header, uint32_t _position );
uint16_t                rtp_get_resolution_marking_width ( struct rtp_ext_header_s* _header, uint32_t _position );

int                     rtp_add_framerate_marking ( rtp_session_t* _session, uint32_t _value );
int                     rtp_remove_framerate_marking ( rtp_session_t* _session );
uint32_t                rtp_get_framerate_marking ( struct rtp_ext_header_s* _header );

/* Convenient functions for marking the payload */
void                    rtp_set_payload_type ( rtp_session_t* _session, uint8_t _payload_value );
uint32_t                rtp_get_payload_type ( rtp_session_t* _session );

#endif /* _RTP__IMPL_H_ */
