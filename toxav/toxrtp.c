/**  toxrtp.c
 *
 *   A little bit off the standard rtp implementation.
 *   Differenece is position of sequence number in a header.
 *   Public functions are prefixed with 'rtp_' while
 *      local-scoped sre marked with 'r_'
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "toxrtp.h"
#include <assert.h>
#include <pthread.h>
#include "../toxcore/util.h"
#include "../toxcore/network.h"

#define PAYLOAD_ID_VALUE_OPUS 1
#define PAYLOAD_ID_VALUE_VP8  2

#define _MAX_SEQU_NUM 65535

#define size_32 4

/**
 * Callback that is called from cores networking poll.
 */

inline __attribute__((always_inline)) void r_increase_nonce(uint8_t* _nonce, uint16_t _target)
{
    int _it = 1;
    while ( _it < crypto_box_NONCEBYTES ) _it += ++_nonce[crypto_box_NONCEBYTES - _it] ? crypto_box_NONCEBYTES : 1;
}

inline __attribute__((always_inline)) void r_store_msg ( rtp_session_t* _session, rtp_msg_t* _msg )
{
    if ( r_check_late_message(_session, _msg) < 0 ) {
        _session->_remote_sequence_number = _msg->_header->_sequence_number;
        _session->_current_timestamp = _msg->_header->_timestamp;
    }

    pthread_mutex_lock(&_session->_mutex);

    if ( _session->_last_msg ) {
        _session->_last_msg->_next = _msg;
        _session->_last_msg = _msg;
    } else {
        _session->_last_msg = _session->_oldest_msg = _msg;
    }

    pthread_mutex_unlock(&_session->_mutex);
}

int rtp_handlepacket ( void* _object, tox_IP_Port ip_port, uint8_t* data, uint32_t length )
{
    rtp_session_t* _session = _object;
    rtp_msg_t* _msg;

    if ( !_session )
        return -1;

    uint8_t plain[MAX_UDP_PACKET_SIZE];

    uint16_t _sequence_num = ( ( uint16_t ) data[1] << 8 ) | data[2];

    /* Clculate the right nonce */
    uint8_t _calculated[crypto_box_NONCEBYTES];
    memcpy(_calculated, _session->_decrypt_nonce, crypto_box_NONCEBYTES);
    r_increase_nonce( _calculated, _sequence_num - 1 );

    /* Decrypt message */
    int decrypted_length = decrypt_data_symmetric(
        _session->_decrypt_key,
        _calculated,
        data + 3, /* Desc. byte + sequ. num. */
        length - 3,
        plain
        );

    if ( -1 == decrypted_length )
        return -1;

    printf("%d", _sequence_num);

    _msg = rtp_msg_parse ( NULL, _sequence_num, plain, decrypted_length );

    if ( !_msg )
        return 0;

    r_store_msg(_session, _msg);

    return 0;
}

/**
 * PAYLOAD TABLE
 */

static const uint32_t r_payload_table[] =
{
    8000, 8000, 8000, 8000, 8000, 8000, 16000, 8000, 8000, 8000,    /*    0-9    */
    44100, 44100, 0, 0, 90000, 8000, 11025, 22050, 0, 0,            /*   10-19   */
    0, 0, 0, 0, 0, 90000, 90000, 0, 90000, 0,                       /*   20-29   */
    0, 90000, 90000, 90000, 90000, 0, 0, 0, 0, 0,                   /*   30-39   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   40-49   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   50-59   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   60-69   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   70-79   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   80-89   */
    0, 0, 0, 0, 0, 0, PAYLOAD_ID_VALUE_OPUS, 0, 0, 0,               /*   90-99   */
    0, 0, 0, 0, 0, 0, PAYLOAD_ID_VALUE_VP8, 0, 0, 0,                /*  100-109  */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*  110-119  */
    0, 0, 0, 0, 0, 0, 0, 0                                          /*  120-127  */
};

/* Current compatibility solution */
int m_sendpacket(Networking_Core* _core_handler, void *ip_port, uint8_t *data, uint32_t length)
{
    return sendpacket(_core_handler, *((IP_Port*) ip_port), data, length);
}

/**
 * BASIC WORK WITH RTP SESSION
 */

inline __attribute__((always_inline)) int r_check_late_message (rtp_session_t* _session, rtp_msg_t* _msg)
{
    /*
     * Check Sequence number. If this new msg has lesser number then the _session->_last_sequence_number
     * it shows that the message came in late
     */
    if ( _msg->_header->_sequence_number < _session->_remote_sequence_number &&
         _msg->_header->_timestamp < _session->_current_timestamp
       ) {
        return 0;
    }
    return -1;
}

rtp_session_t* rtp_init_session ( void* _net_core, int payload_type )
{
    rtp_session_t* _retu = calloc(sizeof(rtp_session_t), 1);
    assert(_retu);

    networking_registerhandler(_net_core, payload_type, rtp_handlepacket, _retu);

    _retu->_version = RTP_VERSION;   /* It's always 2 */
    _retu->_padding = 0;             /* If some additional data is needed about the packet */
    _retu->_extension = 0;           /* If extension to header is needed */
    _retu->_cc        = 1;           /* It basically represents amount of contributors */
    _retu->_csrc      = NULL;        /* Container */
    _retu->_ssrc      = randombytes_random();
    _retu->_marker    = 0;
    _retu->_payload_type = 0;        /* You should specify payload type */

    /* RFC suggests that sequence number starts at random number
     * and goes to _MAX_SEQU_NUM, however placing sequence at 1
     * on both sides simplifies encryption and it doesn't play much of
     * a role here.
     */
    _retu->_remote_sequence_number = _retu->_sequence_number = 1;

    _retu->_ext_header = NULL; /* When needed allocate */
    _retu->_exthdr_framerate = -1;
    _retu->_exthdr_resolution = -1;

    _retu->_encrypt_key = _retu->_decrypt_key = NULL;
    _retu->_encrypt_nonce = _retu->_decrypt_nonce = NULL;

    _retu->_csrc = calloc(sizeof(uint32_t), 1);
    assert(_retu->_csrc);

    _retu->_csrc[0] = _retu->_ssrc; /* Set my ssrc to the list receive */

    _retu->_prefix = payload_type;

    _retu->_oldest_msg = _retu->_last_msg = NULL;

    pthread_mutex_init(&_retu->_mutex, NULL);
    /*
     *
     */
    return _retu;
}

int rtp_terminate_session ( rtp_session_t* _session )
{
    if ( !_session )
        return -1;

    free ( _session->_ext_header );
    free ( _session->_csrc );

    pthread_mutex_destroy(&_session->_mutex);

    /* And finally free session */
    free ( _session );

    return 0;
}

void rtp_free_msg ( rtp_session_t* _session, rtp_msg_t* _message )
{
    free ( _message->_data );

    if ( !_session ){
        free ( _message->_header->_csrc );
        if ( _message->_ext_header ){
            free ( _message->_ext_header->_hd_ext );
            free ( _message->_ext_header );
        }
    } else {
        if ( _session->_csrc != _message->_header->_csrc )
            free ( _message->_header->_csrc );
        if ( _message->_ext_header && _session->_ext_header != _message->_ext_header ) {
            free ( _message->_ext_header->_hd_ext );
            free ( _message->_ext_header );
        }
    }

    free ( _message->_header );
    free ( _message );
}


int rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* _msg, void* _core_handler )
{
    if ( !_msg  || _msg->_data == NULL || _msg->_length <= 0 ) {
        return -1;
    }

    uint8_t _send_data [ MAX_UDP_PACKET_SIZE ];

    _send_data[0] = _session->_prefix;

    int encrypted_length = encrypt_data_symmetric(
        _session->_encrypt_key,
        _session->_encrypt_nonce,
        _msg->_data + 2, /* Skip 2 bytes that are for sequnum */
        _msg->_length - 2,
        _send_data + 3
        );

    _send_data[1] = _msg->_data[0];
    _send_data[2] = _msg->_data[1];

    if ( 0 > m_sendpacket ( _core_handler, &_session->_dest, _send_data, encrypted_length + 3) ) {
        printf("Stderror: %s", strerror(errno));
    }


    /* Set sequ number */
    if ( _session->_sequence_number >= _MAX_SEQU_NUM ) {
        _session->_sequence_number = 0;
    } else {
        _session->_sequence_number++;
    }

    /* Generate new nonce */
    r_increase_nonce(_session->_encrypt_nonce, 1);

    rtp_free_msg ( _session, _msg );
    return 0;
}

rtp_msg_t* rtp_recv_msg ( rtp_session_t* _session )
{
    if ( !_session )
        return NULL;

    rtp_msg_t* _retu = _session->_oldest_msg;

    pthread_mutex_lock(&_session->_mutex);

    if ( _retu )
        _session->_oldest_msg = _retu->_next;

    if ( !_session->_oldest_msg )
        _session->_last_msg = NULL;

    pthread_mutex_unlock(&_session->_mutex);

    return _retu;
}

int rtp_release_session_recv ( rtp_session_t* _session )
{
    if ( !_session ){
        return -1;
    }

    rtp_msg_t* _tmp,* _it;

    pthread_mutex_lock(&_session->_mutex);

    for ( _it = _session->_oldest_msg; _it; _it = _tmp ){
        _tmp = _it->_next;
        rtp_free_msg(_session, _it);
    }

    _session->_last_msg = _session->_oldest_msg = NULL;

    pthread_mutex_unlock(&_session->_mutex);

    return 0;
}

/**
 * HEADERS MANIPULATION
 */

#define r_add_flag_version(_h, _v) do { ( _h->_flags ) &= 0x3F; ( _h->_flags ) |= ( ( ( _v ) << 6 ) & 0xC0 ); } while(0)
#define r_add_flag_padding(_h, _v) do { if ( _v > 0 ) _v = 1; ( _h->_flags ) &= 0xDF; ( _h->_flags ) |= ( ( ( _v ) << 5 ) & 0x20 ); } while(0)
#define r_add_flag_extension(_h, _v) do { if ( _v > 0 ) _v = 1; ( _h->_flags ) &= 0xEF;( _h->_flags ) |= ( ( ( _v ) << 4 ) & 0x10 ); } while(0)
#define r_add_flag_CSRCcount(_h, _v) do { ( _h->_flags ) &= 0xF0; ( _h->_flags ) |= ( ( _v ) & 0x0F ); } while(0)
#define r_add_setting_marker(_h, _v) do { if ( _v > 1 ) _v = 1; ( _h->_marker_payloadt ) &= 0x7F; ( _h->_marker_payloadt ) |= ( ( ( _v ) << 7 ) /*& 0x80 */ ); } while(0)
#define r_add_setting_payload(_h, _v) do { if ( _v > 127 ) _v = 127; ( _h->_marker_payloadt ) &= 0x80; ( _h->_marker_payloadt ) |= ( ( _v ) /* & 0x7F */ ); } while(0)

#define r_get_flag_version(_h) (( _h->_flags & 0xd0 ) >> 6)
#define r_get_flag_padding(_h) (( _h->_flags & 0x20 ) >> 5)
#define r_get_flag_extension(_h) (( _h->_flags & 0x10 ) >> 4)
#define r_get_flag_CSRCcount(_h) ( _h->_flags & 0x0f )
#define r_get_setting_marker(_h) (( _h->_marker_payloadt ) >> 7)
#define r_get_setting_payload(_h) ((_h->_marker_payloadt) & 0x7f)

/**
 * MESSAGE MANIPULATION
 */

inline __attribute__((always_inline)) rtp_header_t* r_extract_header ( const uint8_t* _payload, size_t _bytes )
{
    if ( !_payload ) {
        return NULL;
    }

    const uint8_t* _it = _payload;

    rtp_header_t* _retu = calloc(sizeof(rtp_header_t), 1);
    assert(_retu);

    /* Extract sequence number ( now is done directly in rtp_parse_msg )
    _retu->_sequence_number = ( ( uint16_t ) * _it << 8 ) | * ( _it + 1 );
    _it += 2; */


    _retu->_flags = *_it; ++_it;


    /* This indicates if the first 2 bytes are valid.
     * Now it my happen that this is out of order but
     * it cuts down chances of parsing some invalid value
     */
    if ( r_get_flag_version(_retu) != RTP_VERSION ){
        /* Deallocate */
        free(_retu);
        return NULL;
    }

    /*
     * Added a check for the size of the header little sooner so
     * I don't need to parse the other stuff if it's bad
     */
    uint8_t cc = r_get_flag_CSRCcount ( _retu );
    uint32_t _lenght = 12 /* Minimum header len */ + ( cc * 4 );

    if ( _bytes < _lenght ) {
        /* Deallocate */
        free(_retu);
        return NULL;
    }

    if ( cc > 0 ) {
        _retu->_csrc = calloc ( sizeof ( uint32_t ), cc );
        assert(_retu->_csrc);

    } else { /* But this should not happen ever */
        /* Deallocate */
        free(_retu);
        return NULL;
    }


    _retu->_marker_payloadt = *_it; ++_it;
    _retu->_length = _lenght;

    _retu->_timestamp = ( ( uint32_t ) * _it         << 24 ) |
                        ( ( uint32_t ) * ( _it + 1 ) << 16 ) |
                        ( ( uint32_t ) * ( _it + 2 ) << 8 )  |
                        (              * ( _it + 3 ) ) ;

    _it += 4;

    _retu->_ssrc = ( ( uint32_t ) * _it         << 24 ) |
                   ( ( uint32_t ) * ( _it + 1 ) << 16 ) |
                   ( ( uint32_t ) * ( _it + 2 ) << 8 )  |
                   ( ( uint32_t ) * ( _it + 3 ) ) ;


    size_t x;
    for ( x = 0; x < cc; x++ ) {
        _it += 4;
        _retu->_csrc[x] = ( ( uint32_t ) * _it          << 24 ) |
                          ( ( uint32_t ) * ( _it + 1 )  << 16 ) |
                          ( ( uint32_t ) * ( _it + 2 )  << 8 )  |
                          ( ( uint32_t ) * ( _it + 3 ) ) ;
    }

    return _retu;
}

inline __attribute__((always_inline)) rtp_ext_header_t* r_extract_ext_header ( const uint8_t* _payload, size_t _bytes )
{
    if ( !_payload ) {
        return NULL;
    }

    const uint8_t* _it = _payload;

    rtp_ext_header_t* _retu = calloc(sizeof(rtp_ext_header_t), 1);
    assert(_retu);

    uint16_t _ext_len = ( ( uint16_t ) * _it << 8 ) | * ( _it + 1 ); _it += 2;

    if ( _bytes < ( _ext_len * sizeof(uint32_t) ) ) {
        return NULL;
    }

    _retu->_ext_len  = _ext_len;
    _retu->_ext_type = ( ( uint16_t ) * _it << 8 ) | * ( _it + 1 ); _it -= 2;

    _retu->_hd_ext = calloc(sizeof(uint32_t), _ext_len);
    assert(_retu->_hd_ext);

    uint32_t* _hd_ext = _retu->_hd_ext;
    size_t i;
    for ( i = 0; i < _ext_len; i++ ) {
        _it += 4;
        _hd_ext[i] = ( ( uint32_t ) * _it         << 24 ) |
                     ( ( uint32_t ) * ( _it + 1 ) << 16 ) |
                     ( ( uint32_t ) * ( _it + 2 ) << 8 )  |
                     ( ( uint32_t ) * ( _it + 3 ) ) ;
    }

    return _retu;
}

inline __attribute__((always_inline)) uint8_t* r_add_header ( rtp_header_t* _header, uint8_t* _payload )
{
    uint8_t cc = r_get_flag_CSRCcount ( _header );

    uint8_t* _it = _payload;


    /* Add sequence number first */
    *_it = ( _header->_sequence_number >> 8 ); ++_it;
    *_it = ( _header->_sequence_number ); ++_it;

    *_it = _header->_flags; ++_it;
    *_it = _header->_marker_payloadt; ++_it;


    uint32_t _timestamp = _header->_timestamp;
    *_it = ( _timestamp >> 24 ); ++_it;
    *_it = ( _timestamp >> 16 ); ++_it;
    *_it = ( _timestamp >> 8 ); ++_it;
    *_it = ( _timestamp ); ++_it;

    uint32_t _ssrc = _header->_ssrc;
    *_it = ( _ssrc >> 24 ); ++_it;
    *_it = ( _ssrc >> 16 ); ++_it;
    *_it = ( _ssrc >> 8 ); ++_it;
    *_it = ( _ssrc );

    uint32_t *_csrc = _header->_csrc;
    size_t x;
    for ( x = 0; x < cc; x++ ) {
        ++_it;
        *_it = ( _csrc[x] >> 24 );  ++_it;
        *_it = ( _csrc[x] >> 16 );  ++_it;
        *_it = ( _csrc[x] >> 8 );   ++_it;
        *_it = ( _csrc[x] );
    }

    return _it;
}

inline __attribute__((always_inline)) uint8_t* r_add_extention_header ( rtp_ext_header_t* _header, uint8_t* _payload )
{
    uint8_t* _it = _payload;

    *_it = ( _header->_ext_len >> 8 ); _it++;
    *_it = ( _header->_ext_len ); _it++;

    *_it = ( _header->_ext_type >> 8 ); ++_it;
    *_it = ( _header->_ext_type );

    size_t x;

    uint32_t* _hd_ext = _header->_hd_ext;
    for ( x = 0; x < _header->_ext_len; x++ ) {
        ++_it;
        *_it = ( _hd_ext[x] >> 24 );  ++_it;
        *_it = ( _hd_ext[x] >> 16 );  ++_it;
        *_it = ( _hd_ext[x] >> 8 );  ++_it;
        *_it = ( _hd_ext[x] );
    }

    return _it;
}

inline __attribute__((always_inline)) rtp_header_t* r_build_header ( rtp_session_t* _session )
{
    rtp_header_t* _retu;
    _retu = calloc ( sizeof * _retu, 1 );
    assert(_retu);

    r_add_flag_version ( _retu, _session->_version );
    r_add_flag_padding ( _retu, _session->_padding );
    r_add_flag_extension ( _retu, _session->_extension );
    r_add_flag_CSRCcount ( _retu, _session->_cc );
    r_add_setting_marker ( _retu, _session->_marker );
    r_add_setting_payload ( _retu, _session->_payload_type );

    _retu->_sequence_number = _session->_sequence_number;
    _retu->_timestamp = ((uint32_t)(current_time() / 1000)); /* micro to milli */
    _retu->_ssrc = _session->_ssrc;

    if ( _session->_cc > 0 ) {
        _retu->_csrc = calloc(sizeof(uint32_t), _session->_cc);
        assert(_retu->_csrc);

        int i;

        for ( i = 0; i < _session->_cc; i++ ) {
            _retu->_csrc[i] = _session->_csrc[i];
        }
    } else {
        _retu->_csrc = NULL;
    }

    _retu->_length = 12 /* Minimum header len */ + ( _session->_cc * size_32 );

    return _retu;
}


/**
 * HERE IS WHERE PARSING IS DONE
 */

rtp_msg_t* rtp_msg_new ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length )
{
    if ( !_session )
        return NULL;

    uint8_t* _from_pos;
    rtp_msg_t* _retu = calloc(sizeof(rtp_msg_t), 1);
    assert(_retu);

    /* Sets header values and copies the extension header in _retu */
    _retu->_header = r_build_header ( _session ); /* It allocates memory and all */
    _retu->_ext_header = _session->_ext_header;


    uint32_t _total_lenght = _length + _retu->_header->_length;

    if ( _retu->_ext_header ) {
        _total_lenght += ( 4 /* Minimum ext header len */ + _retu->_ext_header->_ext_len * size_32 );
        /* Allocate Memory for _retu->_data */
        _retu->_data = calloc ( sizeof _retu->_data, _total_lenght );
        assert(_retu->_data);

        _from_pos = r_add_header ( _retu->_header, _retu->_data );
        _from_pos = r_add_extention_header ( _retu->_ext_header, _from_pos + 1 );
    } else {
        /* Allocate Memory for _retu->_data */
        _retu->_data = calloc ( sizeof _retu->_data, _total_lenght );
        assert(_retu->_data);

        _from_pos = r_add_header ( _retu->_header, _retu->_data );
    }

    /*
     * Parses the extension header into the message
     * Of course if any
     */

    /* Appends _data on to _retu->_data */
    memcpy ( _from_pos + 1, _data, _length );

    _retu->_length = _total_lenght;

    _retu->_next = NULL;

    return _retu;
}

rtp_msg_t* rtp_msg_parse ( rtp_session_t* _session, uint16_t _sequnum, const uint8_t* _data, uint32_t _length )
{
    assert(_length != -1);

    rtp_msg_t* _retu = calloc(sizeof(rtp_msg_t), 1);
    assert(_retu);

    _retu->_header = r_extract_header ( _data, _length ); /* It allocates memory and all */

    if ( !_retu->_header ){
        free(_retu);
        return NULL;
    }
    _retu->_header->_sequence_number = _sequnum;

    _retu->_length = _length - _retu->_header->_length;

    uint16_t _from_pos = _retu->_header->_length - 2 /* Since sequ num is excluded */ ;


    if ( r_get_flag_extension ( _retu->_header ) ) {
        _retu->_ext_header = r_extract_ext_header ( _data + _from_pos, _length );
        if ( _retu->_ext_header ){
            _retu->_length -= ( 4 /* Minimum ext header len */ + _retu->_ext_header->_ext_len * size_32 );
            _from_pos += ( 4 /* Minimum ext header len */ + _retu->_ext_header->_ext_len * size_32 );
        } else {
            free (_retu->_ext_header);
            free (_retu->_header);
            free (_retu);
            return NULL;
        }
    } else {
        _retu->_ext_header = NULL;
    }

    /* Get the payload */
    _retu->_data = calloc ( sizeof ( uint8_t ), _retu->_length );
    assert(_retu->_data);

    memcpy ( _retu->_data, _data + _from_pos, _length - _from_pos );

    _retu->_next = NULL;


    if ( _session && r_check_late_message(_session, _retu) < 0 ){
        _session->_remote_sequence_number = _retu->_header->_sequence_number;
        _session->_current_timestamp = _retu->_header->_timestamp;
    }

    return _retu;
}




/**
 FUNCTIONS BELOW ARE DEPRECATED AND WILL BE REMOVED IN LATER COMMITS
 */

uint16_t rtp_get_resolution_marking_height ( rtp_ext_header_t* _header, uint32_t _position )
{
    if ( _header->_ext_type & RTP_EXT_TYPE_RESOLUTION )
        return _header->_hd_ext[_position];
    else
        return 0;
}

uint16_t rtp_get_resolution_marking_width ( rtp_ext_header_t* _header, uint32_t _position )
{
    if ( _header->_ext_type & RTP_EXT_TYPE_RESOLUTION )
        return ( _header->_hd_ext[_position] >> 16 );
    else
        return 0;
}

int rtp_add_resolution_marking ( rtp_session_t* _session, uint16_t _width, uint16_t _height )
{
    if ( !_session )
        return -1;

    rtp_ext_header_t* _ext_header = _session->_ext_header;
    _session->_exthdr_resolution = 0;

    if ( ! ( _ext_header ) ) {
        _session->_ext_header = calloc (sizeof(rtp_ext_header_t), 1);
        assert(_session->_ext_header);

        _session->_extension = 1;
        _session->_ext_header->_ext_len = 1;
        _ext_header = _session->_ext_header;
        _session->_ext_header->_hd_ext = calloc(sizeof(uint32_t), 1);
        assert(_session->_ext_header->_hd_ext);

    } else { /* If there is need for more headers this will be needed to change */
        if ( !(_ext_header->_ext_type & RTP_EXT_TYPE_RESOLUTION) ){
            uint32_t _exthdr_framerate = _ext_header->_hd_ext[_session->_exthdr_framerate];
            /* it's position is at 2nd place by default */
            _session->_exthdr_framerate ++;

            /* Update length */
            _ext_header->_ext_len++;

            /* Allocate the value */
            _ext_header->_hd_ext = realloc(_ext_header->_hd_ext, sizeof(rtp_ext_header_t) * _ext_header->_ext_len);
            assert(_ext_header->_hd_ext);

            /* Reset other values */
            _ext_header->_hd_ext[_session->_exthdr_framerate] = _exthdr_framerate;
        }
    }

    /* Add flag */
    _ext_header->_ext_type |= RTP_EXT_TYPE_RESOLUTION;

    _ext_header->_hd_ext[_session->_exthdr_resolution] = _width << 16 | ( uint32_t ) _height;

    return 0;
}

int rtp_remove_resolution_marking ( rtp_session_t* _session )
{
    if ( _session->_extension == 0 || ! ( _session->_ext_header ) ) {
        return -1;
    }

    if ( !( _session->_ext_header->_ext_type & RTP_EXT_TYPE_RESOLUTION ) ) {
        return -1;
    }

    _session->_ext_header->_ext_type &= ~RTP_EXT_TYPE_RESOLUTION; /* Remove the flag */
    _session->_exthdr_resolution = -1; /* Remove identifier */

    /* Check if extension is empty */
    if ( _session->_ext_header->_ext_type == 0 ){

        free ( _session->_ext_header->_hd_ext );
        free ( _session->_ext_header );

        _session->_ext_header = NULL; /* It's very important */
        _session->_extension = 0;

    } else {
        _session->_ext_header->_ext_len --;

        /* this will also be needed to change if there are more than 2 headers */
        if ( _session->_ext_header->_ext_type & RTP_EXT_TYPE_FRAMERATE ){
            memcpy(_session->_ext_header->_hd_ext + 1, _session->_ext_header->_hd_ext, _session->_ext_header->_ext_len);
            _session->_exthdr_framerate = 0;
            _session->_ext_header->_hd_ext = realloc( _session->_ext_header->_hd_ext, sizeof( rtp_ext_header_t ) * _session->_ext_header->_ext_len );
            assert(_session->_ext_header->_hd_ext);
        }
    }

    return 0;
}

int rtp_add_framerate_marking ( rtp_session_t* _session, uint32_t _value )
{
    if ( !_session )
        return -1;

    rtp_ext_header_t* _ext_header = _session->_ext_header;
    _session->_exthdr_framerate = 0;

    if ( ! ( _ext_header ) ) {
        _session->_ext_header = calloc (sizeof(rtp_ext_header_t), 1);
        assert(_session->_ext_header);

        _session->_extension = 1;
        _session->_ext_header->_ext_len = 1;
        _ext_header = _session->_ext_header;
        _session->_ext_header->_hd_ext = calloc(sizeof(uint32_t), 1);
        assert(_session->_ext_header->_hd_ext);
    } else { /* If there is need for more headers this will be needed to change */
        if ( !(_ext_header->_ext_type & RTP_EXT_TYPE_FRAMERATE) ){
            /* it's position is at 2nd place by default */
            _session->_exthdr_framerate ++;

            /* Update length */
            _ext_header->_ext_len++;

            /* Allocate the value */
            _ext_header->_hd_ext = realloc(_ext_header->_hd_ext, sizeof(rtp_ext_header_t) * _ext_header->_ext_len);
            assert(_ext_header->_hd_ext);

        }
    }

    /* Add flag */
    _ext_header->_ext_type |= RTP_EXT_TYPE_FRAMERATE;

    _ext_header->_hd_ext[_session->_exthdr_framerate] = _value;

    return 0;
}


int rtp_remove_framerate_marking ( rtp_session_t* _session )
{
    if ( _session->_extension == 0 || ! ( _session->_ext_header ) ) {
        return -1;
    }

    if ( !( _session->_ext_header->_ext_type & RTP_EXT_TYPE_FRAMERATE ) ) {
        return -1;
    }

    _session->_ext_header->_ext_type &= ~RTP_EXT_TYPE_FRAMERATE; /* Remove the flag */
    _session->_exthdr_framerate = -1; /* Remove identifier */
    _session->_ext_header->_ext_len --;

    /* Check if extension is empty */
    if ( _session->_ext_header->_ext_type == 0 ){

        free ( _session->_ext_header->_hd_ext );
        free ( _session->_ext_header );

        _session->_ext_header = NULL; /* It's very important */
        _session->_extension = 0;

    } else if ( !_session->_ext_header->_ext_len ) {

        /* this will also be needed to change if there are more than 2 headers */
        _session->_ext_header->_hd_ext = realloc( _session->_ext_header->_hd_ext, sizeof( rtp_ext_header_t ) * _session->_ext_header->_ext_len );
        assert(_session->_ext_header->_hd_ext);

    }

    return 0;
}

uint32_t rtp_get_framerate_marking ( rtp_ext_header_t* _header )
{
    if ( _header->_ext_len == 1 ){
        return _header->_hd_ext[0];
    } else {
        return _header->_hd_ext[1];
    }
}


void rtp_set_payload_type ( rtp_session_t* _session, uint8_t _payload_value )
{
    _session->_payload_type = _payload_value;
}
uint32_t rtp_get_payload_type ( rtp_session_t* _session )
{
    return r_payload_table[_session->_payload_type];
}
