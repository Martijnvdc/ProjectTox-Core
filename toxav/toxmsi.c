
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define _BSD_SOURCE

#include "toxmsi.h"
#include "../toxcore/util.h"
#include "../toxcore/network.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/event.h"

#include <assert.h>
#include <unistd.h>
#include <string.h>

/* Macros makes stuff easier */
#define same(x, y) strcmp((const char*) x, (const char*) y) == 0

#define MSI_MAXMSG_SIZE 1500

#define TYPE_REQUEST 1
#define TYPE_RESPONSE 2

#define VERSION_STRING "0.2.3"
#define VERSION_STRLEN 5

#define CT_AUDIO_HEADER_VALUE "AUDIO"
#define CT_VIDEO_HEADER_VALUE "VIDEO"


/**
 * Protocol looks like this:
 *
 * | desc. ( 1 byte ) | length ( 2 bytes ) | value ( lenght bytes ) |
 *
 * ie.
 *
 * | 0x1 | 0x0 0x7 | "version"
 *
 * Means: it's field value with length of 7 bytes and value of "version"
 * It's similar to amp protocol
 */


/********** Function declaration **********/

struct msi_msg_s* msi_msg_new ( uint8_t _type, const uint8_t* _typeid );
struct msi_msg_s* msi_parse_msg ( const uint8_t* _data );
uint16_t msi_msg_output ( struct msi_msg_s* _msg, uint8_t* _dest );
void* msi_poll_stack ( void* _session_p );

/*********************************************************/


/** SEND CALLBACK */
int ( *msi_send_message_callback ) ( void* _net_core, tox_IP_Port,  uint8_t*, uint32_t ) = NULL;
void msi_register_callback_send ( int ( *callback ) ( void* _net_core, tox_IP_Port, uint8_t*, uint32_t ) )
{
    msi_send_message_callback = callback;
}

/** MSI CALLBACKS */
static msi_callback_t msi_callback[9] = {0};
void msi_register_callback(msi_callback_t _callback, callbackid_t _id)
{
    msi_callback[_id] = _callback;
}



/********** Header types/parsing **********/

/* define strings for the identifiers */
#define _VERSION_FIELD      "Version"
#define _REQUEST_FIELD      "Request"
#define _RESPONSE_FIELD     "Response"
#define _INFO_FIELD         "INFO"
#define _REASON_FIELD       "Reason"
#define _CALLTYPE_FIELD     "Call-type"
#define _USERAGENT_FIELD    "User-agent"
#define _CALLID_FIELD       "Call-id"
#define _CRYPTOKEY_FIELD    "Crypto-key"
#define _NONCE_FIELD        "Nonce"

/* protocol descriptors */
#define end_byte    0x0
#define field_byte  0x1
#define value_byte  0x2

#define GENERIC_HEADER(header) \
typedef struct msi_header_##header##_s { \
uint8_t* _header_value; \
uint16_t _size; \
} msi_header_##header##_t;

GENERIC_HEADER(version)
GENERIC_HEADER(request)
GENERIC_HEADER(response)
GENERIC_HEADER(calltype)
GENERIC_HEADER(useragent)
GENERIC_HEADER(callid)
GENERIC_HEADER(info)
GENERIC_HEADER(reason)
GENERIC_HEADER(cryptokey)
GENERIC_HEADER(nonce)

/*********************************************************/




/********** Message types **********/


typedef enum {
    _invite,
    _start,
    _cancel,
    _reject,
    _end,

} msi_request_t;


typedef struct msi_msg_s {

    msi_header_version_t   _version;
    msi_header_request_t   _request;
    msi_header_response_t  _response;
    msi_header_calltype_t  _calltype;
    msi_header_useragent_t _useragent;
    msi_header_info_t      _info;
    msi_header_reason_t    _reason;
    msi_header_callid_t    _callid;
    msi_header_cryptokey_t _cryptokey;
    msi_header_nonce_t     _nonce;

    struct msi_msg_s* _next;

} msi_msg_t;

static inline const uint8_t *stringify_request(msi_request_t _request)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"INVITE",
        (uint8_t*)"START",
        (uint8_t*)"CANCEL",
        (uint8_t*)"REJECT",
        (uint8_t*)"END"
    };

    return strings[_request];
}

typedef enum {
    _trying,
    _ringing,
    _starting,
    _ending,
    _error

} msi_response_t;

static inline const uint8_t *stringify_response(msi_response_t _response)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"trying",
        (uint8_t*)"ringing",
        (uint8_t*)"starting",
        (uint8_t*)"ending",
        (uint8_t*)"error"
    };

    return strings[_response];
}

/*********************************************************/



/********** Generic functions **********/

/* Define default timeout for a request.
 * There is no behavior specified by the msi on what will
 * client do on timeout, but to call timeout callback.
 */
#define m_deftout 10000 /* in milliseconds */

static const uint8_t MSI_PACKET = 69;

void t_randomstr ( uint8_t* _str, size_t _size )
{
    assert(_str);

    static const uint8_t _bytes[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    int _it = 0;

    for ( ; _it < _size; _it++ ) {
        _str[_it] = _bytes[ randombytes_random() % 61 ];
    }
}

typedef enum {
    error_deadcall = 1,     /* has call id but it's from old call */
    error_id_mismatch,      /* non-existing call */

    error_no_callid,        /* not having call id */
    error_no_call,          /* no call in session */
    error_no_crypto_key,    /* no crypto key */

    error_busy,

} msi_callerror_t;          /* Error codes */

static inline const uint8_t *stringify_error(msi_callerror_t _error_code)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"",
        (uint8_t*)"Using dead call",
        (uint8_t*)"Call id not set to any call",
        (uint8_t*)"Call id not available",
        (uint8_t*)"No active call in session",
        (uint8_t*)"No Crypto-key set",
        (uint8_t*)"Callee busy"
    };

    return strings[_error_code];
}

static inline const uint8_t *stringify_error_code(msi_callerror_t _error_code)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"",
        (uint8_t*)"1",
        (uint8_t*)"2",
        (uint8_t*)"3",
        (uint8_t*)"4",
        (uint8_t*)"5",
        (uint8_t*)"6"
    };

    return strings[_error_code];
}


msi_msg_t* receive_message ( msi_session_t* _session )
{
    assert(_session);


    msi_msg_t* _retu = _session->_oldest_msg;

    pthread_mutex_lock ( &_session->_mutex );

    if ( _retu )
        _session->_oldest_msg = _retu->_next;

    if ( !_session->_oldest_msg )
        _session->_last_msg = NULL;

    pthread_mutex_unlock ( &_session->_mutex );

    return _retu;
}

void msi_store_msg ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);
    assert(_msg);

    pthread_mutex_lock ( &_session->_mutex );

    if ( _session->_last_msg ) {
        _session->_last_msg->_next = _msg;
        _session->_last_msg = _msg;
    } else {
        _session->_last_msg = _session->_oldest_msg = _msg;
    }

    pthread_mutex_unlock ( &_session->_mutex );
}

int msi_send_msg ( msi_session_t* _session, msi_msg_t* _msg )
{
    int _status;

    if ( !_session->_call ) /* Which should never happen */
        return -1;

    msi_msg_set_callid ( _msg, _session->_call->_id, _CALL_ID_LEN );

    uint8_t _msg_string_final [MSI_MAXMSG_SIZE];

    _msg_string_final[0] = 69;
    uint16_t _total = msi_msg_output ( _msg, _msg_string_final + 1 ) + 1;

    _status = ( *msi_send_message_callback )
        ( _session->_net_core, _session->_friend_id, _msg_string_final, _total );

    return _status;
}

int msi_handlepacket ( void* _object, tox_IP_Port ip_port, uint8_t* data, uint32_t length )
{
    msi_session_t* _session = _object;
    msi_msg_t* _msg;

    _msg = msi_parse_msg ( data + 1 ); /* ignore marker byte */

    if ( _msg ) {
        /* my current solution for "hole punching" */
        _session->_friend_id = ip_port;
    } else {
        return -1;
    }

    /* place message in a session */
    msi_store_msg(_session, _msg);

    return 0;
}

void flush_peer_type ( msi_session_t* _session, msi_msg_t* _msg, int _peer_id )
{
    if ( _msg->_calltype._header_value ) {
        if ( strcmp ( ( const char* ) _msg->_calltype._header_value, CT_AUDIO_HEADER_VALUE ) == 0 ) {
            _session->_call->_type_peer[_peer_id] = type_audio;

        } else if ( strcmp ( ( const char* ) _msg->_calltype._header_value, CT_VIDEO_HEADER_VALUE ) == 0 ) {
            _session->_call->_type_peer[_peer_id] = type_video;
        } else {} /* Error */
    } else {} /* Error */
}

/* Always return SUCCESS */
int handle_error(msi_session_t* _session, msi_callerror_t _errid)
{
    msi_msg_t* _msg_error = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _error ) );

    const uint8_t* _error_code_str = stringify_error_code(_errid);

    msi_msg_set_reason(_msg_error, _error_code_str, strlen((const char*)_error_code_str) );
    msi_send_msg ( _session, _msg_error );
    msi_msg_free ( _msg_error );

    _session->_last_error_id = _errid;
    _session->_last_error_str = stringify_error(_errid);

    event.throw(msi_callback[cb_error], _session);

    return 0;
}

int has_call_error ( msi_session_t* _session, msi_msg_t* _msg )
{
    if ( !_msg->_callid._header_value ) {
        return handle_error(_session, error_no_callid );

    } else if ( !_session->_call ) {
        return handle_error(_session, error_no_call );

    } else if ( memcmp(_session->_call->_id, _msg->_callid._header_value, _CALL_ID_LEN ) != 0 ) {
        return handle_error(_session, error_id_mismatch );

    }

    return -1;
}

/* On request timeout call this function
 */
void msi_handle_timeout (void* _arg)
{
    /* Send hangup either way */
    msi_cancel(_arg);
    (*msi_callback[cb_timeout]) (_arg);
    (*msi_callback[cb_ending ]) (_arg);

}

/*********************************************************/



/********** MESSAGE PARSING/HANDLING **********/

#define on_header(_iterator, _header, _descriptor, _size_const) \
( memcmp(_iterator, _descriptor, _size_const) == 0){ /* Okay */ \
    _iterator += _size_const; /* Set _iterator at begining of value part */ \
    if ( *_iterator != value_byte ) \
        { assert(0); return -1; }\
    _iterator ++;\
    uint16_t _value_size = (uint16_t) *(_iterator ) << 8 | \
                           (uint16_t) *(_iterator + 1); \
    _header._header_value = calloc(sizeof(uint8_t), _value_size); \
    _header._size = _value_size; \
    memcpy(_header._header_value, _iterator + 2, _value_size);\
    _iterator = _iterator + 2 + _value_size; /* set _iterator at new header or end_byte */ \
}

int msi_parse_raw_data ( msi_msg_t* _msg, const uint8_t* _data )
{
    assert(_msg);

    const uint8_t* _it = _data;

    while ( *_it ) {/* until end_byte is hit */

        if ( *_it == field_byte ) {
            uint16_t _size = (uint16_t) *(_it + 1) << 8 |
                             (uint16_t) *(_it + 2);

            _it += 3; /*place it at the field value beginning*/

            switch ( _size ) { /* Compare the size of the hardcoded values ( vary fast and convenient ) */

            case 4: /* INFO header */
            {
                if on_header(_it, _msg->_info, _INFO_FIELD, 4)
            } break;

            case 5: /* NONCE header */
            {
                if on_header(_it, _msg->_nonce, _NONCE_FIELD, 5)
            } break;

            case 6: /* Reason header */
            {
                if on_header(_it, _msg->_reason, _REASON_FIELD, 6)
            } break;

            case 7: /* Version, Request, Call-id headers */
            {
                if on_header(_it, _msg->_version, _VERSION_FIELD, 7)
                else if on_header(_it, _msg->_request, _REQUEST_FIELD, 7)
                else if on_header(_it, _msg->_callid, _CALLID_FIELD, 7)
            } break;

            case 8: /* Response header */
            {
                if on_header(_it, _msg->_response, _RESPONSE_FIELD, 8)
            } break;

            case 9: /* Call-type header */
            {
                if on_header(_it, _msg->_calltype, _CALLTYPE_FIELD, 9)
            } break;

            case 10: /* User-agent, Crypto-key headers */
            {
                if on_header(_it, _msg->_useragent, _USERAGENT_FIELD, 10)
                else if on_header(_it, _msg->_cryptokey, _CRYPTOKEY_FIELD, 10)
            } break;

            default: return -1;
            }
        } else return -1;
        /* If it's anything else return failure as the message is invalid */

    }

    return 0;
}

void msi_msg_free ( msi_msg_t* _msg )
{
    assert(_msg);

    free(_msg->_calltype._header_value);
    free(_msg->_request._header_value);
    free(_msg->_response._header_value);
    free(_msg->_useragent._header_value);
    free(_msg->_version._header_value);
    free(_msg->_info._header_value);
    free(_msg->_cryptokey._header_value);
    free(_msg->_nonce._header_value);
    free(_msg->_reason._header_value);
    free(_msg->_callid._header_value);

    free(_msg);
}

#define ALLOCATE_HEADER( _var, _m_header_value, _t_size)   \
_var._header_value = calloc(sizeof *_m_header_value, _t_size);            \
memcpy(_var._header_value, (const uint8_t*)_m_header_value, _t_size);\
_var._size = _t_size;

msi_msg_t* msi_msg_new ( uint8_t _type, const uint8_t* _typeid )
{
    msi_msg_t* _retu = calloc ( sizeof ( msi_msg_t ), 1 );
    assert(_retu);

    memset(_retu, NULL, sizeof(msi_msg_t));

    if ( _type == TYPE_REQUEST ){
        ALLOCATE_HEADER( _retu->_request, _typeid, strlen(_typeid) )

    } else if ( _type == TYPE_RESPONSE ) {
        ALLOCATE_HEADER( _retu->_response, _typeid, strlen(_typeid) )

    } else {
        msi_msg_free(_retu);
        return NULL;
    }

    ALLOCATE_HEADER( _retu->_version, VERSION_STRING, strlen(VERSION_STRING))

    return _retu;
}


msi_msg_t* msi_parse_msg ( const uint8_t* _data )
{
    assert(_data);

    msi_msg_t* _retu = calloc ( sizeof ( msi_msg_t ), 1 );
    assert(_retu);

    memset(_retu, NULL, sizeof(msi_msg_t));

    if ( msi_parse_raw_data ( _retu, _data ) == -1 ){

        msi_msg_free(_retu);
        return NULL;
    }

    if ( !_retu->_version._header_value || VERSION_STRLEN != _retu->_version._size ||
         memcmp(_retu->_version._header_value, VERSION_STRING, VERSION_STRLEN) != 0 ){

         msi_msg_free(_retu);
         return NULL;
    }

    return _retu;
}

/* Returns size added */
uint8_t* append_header_to_string (
    uint8_t* _dest,
    const uint8_t* _header_field,
    const uint8_t* _header_value,
    uint16_t _value_len,
    uint16_t* _lenght )
{
    assert(_dest);
    assert(_header_value);
    assert(_header_field);

    uint8_t* _hvit = _header_value;
    uint16_t _total = 6 + _value_len; /* 6 is known plus header value len + field len*/

    *_dest = field_byte; /* Set the first byte */

    uint8_t* _getback_byte = _dest + 1; /* remeber the byte we were on */
    _dest += 3; /* swith to 4th byte where field value starts */

    /* Now set the field value and calculate it's length */
    uint16_t _i = 0;
    for ( ; _header_field[_i]; ++_i ){
        *_dest = _header_field[_i];
        ++_dest;
    };
    _total += _i;

    /* Now set the length of the field byte */
    *_getback_byte = (uint8_t) _i >> 8; _getback_byte++;
    *_getback_byte = (uint8_t) _i;

    /* for value part do it regulary */
    *_dest = value_byte; _dest++;

    *_dest = (uint8_t) _value_len >> 8; _dest++;
    *_dest = (uint8_t) _value_len; _dest++;

    for ( _i = _value_len; _i; --_i ){
        *_dest = *_hvit; ++_hvit; ++_dest;
    }

    *_lenght += _total;
    return _dest;
}

#define clean_assign(_added, _var, _field, _header)\
if ( _header._header_value ) { \
_var = append_header_to_string(_var, (const uint8_t*)_field, _header._header_value, _header._size, &_added); }

uint16_t msi_msg_output ( msi_msg_t* _msg, uint8_t* _dest )
{
    assert(_msg);
    assert(_dest);

    uint8_t* _iterated = _dest;
    uint16_t _size = 0;

    clean_assign(_size, _iterated, _VERSION_FIELD, _msg->_version);
    clean_assign(_size, _iterated, _REQUEST_FIELD, _msg->_request);
    clean_assign(_size, _iterated, _RESPONSE_FIELD, _msg->_response);
    clean_assign(_size, _iterated, _CALLTYPE_FIELD, _msg->_calltype);
    clean_assign(_size, _iterated, _USERAGENT_FIELD, _msg->_useragent);
    clean_assign(_size, _iterated, _INFO_FIELD, _msg->_info);
    clean_assign(_size, _iterated, _CALLID_FIELD, _msg->_callid);
    clean_assign(_size, _iterated, _REASON_FIELD, _msg->_reason);
    clean_assign(_size, _iterated, _CRYPTOKEY_FIELD, _msg->_cryptokey);
    clean_assign(_size, _iterated, _NONCE_FIELD, _msg->_nonce);

    *_iterated = end_byte;
    _size ++;

    return _size;
}

/* Header manipulation */

#define GENERIC_SETTER_DEFINITION(header) \
void msi_msg_set_##header ( msi_msg_t* _msg, const uint8_t* _header_value, uint16_t _size ) \
{ assert(_msg); assert(_header_value); \
  free(_msg->_##header._header_value); \
  ALLOCATE_HEADER( _msg->_##header, _header_value, _size )}

GENERIC_SETTER_DEFINITION(calltype)
GENERIC_SETTER_DEFINITION(useragent)
GENERIC_SETTER_DEFINITION(reason)
GENERIC_SETTER_DEFINITION(info)
GENERIC_SETTER_DEFINITION(callid)
GENERIC_SETTER_DEFINITION(cryptokey)
GENERIC_SETTER_DEFINITION(nonce)

/*********************************************************/








/********** Initiation and termination of the control structures **********/
msi_session_t* msi_init_session ( void* _net_core, const uint8_t* _user_agent )
{
    assert(_net_core);
    assert(_user_agent);

    msi_session_t* _session = calloc ( sizeof ( msi_session_t ), 1 );
    assert(_session);

    _session->_oldest_msg = _session->_last_msg = NULL;
    _session->_net_core = _net_core;

    _session->_user_agent = _user_agent;
    _session->_agent_handler = NULL;

    _session->_call = NULL;

    _session->_frequ = 10000; /* default value? */
    _session->_call_timeout = 30000; /* default value? */

    _session->_running = 1;
    pthread_mutex_init ( &_session->_mutex, NULL );

    networking_registerhandler(_net_core, MSI_PACKET, msi_handlepacket, _session);

    if ( 0 != event.throw(msi_poll_stack, _session) )
    {
        printf ( "Error while starting main loop: %d, %s\n", errno, strerror ( errno ) );
        free(_session);
        return NULL;
    }

    return _session;
}

int msi_terminate_session ( msi_session_t* _session )
{
    assert(_session);

    int _status = 0;

    msi_terminate_call(_session);

    _session->_running = 0;
    while ( _session->_running >= 0 ) usleep(_session->_frequ); /* wait for exit */

    pthread_mutex_destroy ( &_session->_mutex );

    free ( _session );
    return _status;
}


msi_call_t* msi_init_call ( msi_session_t* _session, int _peers, int _ringing_timeout )
{
    assert(_session);
    assert(_peers);

    msi_call_t* _call = calloc ( sizeof ( msi_call_t ), 1 );
    _call->_type_peer = calloc ( sizeof ( call_type ), _peers );

    assert(_call);
    assert(_call->_type_peer);

    _call->_participants = _peers;

    _call->_request_timer_id = 0;
    _call->_ringing_timer_id = 0;

    _call->_key_local = NULL;
    _call->_key_peer = NULL;
    _call->_nonce_local = NULL;
    _call->_nonce_peer = NULL;

    _call->_ringing_tout_ms = _ringing_timeout;

    pthread_mutex_init ( &_call->_mutex, NULL );

    return _call;
}

int msi_terminate_call ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call )
        return -1;


    /* Check event loop and cancel timed events if there are any
     * Notice: This has to be done before possibly
     * locking the mutex the second time
     */
    event.timer_release(_session->_call->_request_timer_id);
    event.timer_release(_session->_call->_ringing_timer_id);

/* Get a handle */
pthread_mutex_lock(&_session->_call->_mutex);

    msi_call_t* _call = _session->_call;
    _session->_call = NULL;

    free ( _call->_type_peer );
    free ( _call->_key_local );
    free ( _call->_key_peer );

/* Release handle */
pthread_mutex_unlock(&_call->_mutex);

    pthread_mutex_destroy ( &_call->_mutex );

    free ( _call );

    return 0;
}

/*********************************************************/


/********** Request handlers **********/

int msi_handle_recv_invite ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( _session->_call ) {
        handle_error(_session, error_busy);
        return 0;
    }
    if ( !_msg->_callid._header_value ) {
        handle_error(_session, error_no_callid);
        return 0;
    }

    _session->_call = msi_init_call ( _session, 1, 0 );
    memcpy(_session->_call->_id, _msg->_callid._header_value, _CALL_ID_LEN);
    _session->_call->_state = call_starting;

    flush_peer_type ( _session, _msg, 0 );

    msi_msg_t* _msg_ringing = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _ringing ) );
    msi_send_msg ( _session, _msg_ringing );
    msi_msg_free ( _msg_ringing );

    event.throw(msi_callback[cb_oninvite], _session);

    return 1;
}
int msi_handle_recv_start ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    if ( !_msg->_cryptokey._header_value )
        return handle_error(_session, error_no_crypto_key);

    _session->_call->_state = call_active;

    _session->_call->_key_peer = calloc( sizeof(uint8_t), crypto_secretbox_KEYBYTES );
    memcpy(_session->_call->_key_peer, _msg->_cryptokey._header_value, crypto_secretbox_KEYBYTES);

    _session->_call->_nonce_peer = calloc( sizeof(uint8_t), crypto_box_NONCEBYTES );
    memcpy(_session->_call->_nonce_peer, _msg->_nonce._header_value,  crypto_box_NONCEBYTES);

    flush_peer_type ( _session, _msg, 0 );

    event.throw(msi_callback[cb_onstart], _session);

    return 1;
}
int msi_handle_recv_reject ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;


    msi_msg_t* _msg_end = msi_msg_new ( TYPE_REQUEST, stringify_request ( _end ) );
    msi_send_msg ( _session, _msg_end );
    msi_msg_free ( _msg_end );

    event.timer_release(_session->_call->_request_timer_id);
    event.throw(msi_callback[cb_onreject], _session);
    _session->_call->_request_timer_id = event.timer_alloc(msi_handle_timeout, _session, m_deftout);

    return 1;
}
int msi_handle_recv_cancel ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;


    msi_terminate_call ( _session );

    event.throw(msi_callback[cb_oncancel], _session);

    return 1;
}
int msi_handle_recv_end ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;


    msi_msg_t* _msg_ending = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _ending ) );
    msi_send_msg ( _session, _msg_ending );
    msi_msg_free ( _msg_ending );

    msi_terminate_call ( _session );

    event.throw(msi_callback[cb_onend], _session);

    return 1;
}

/*********************************************************/

/********** Response handlers **********/
int msi_handle_recv_ringing ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    _session->_call->_ringing_timer_id = event.timer_alloc(msi_handle_timeout, _session, _session->_call->_ringing_tout_ms );
    event.throw(msi_callback[cb_ringing], _session);

    return 1;
}
int msi_handle_recv_starting ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    if ( !_msg->_cryptokey._header_value ){
        return handle_error(_session, error_no_crypto_key);
    }

    /* Generate local key/nonce to send */
    _session->_call->_key_local = calloc( sizeof(uint8_t), crypto_secretbox_KEYBYTES );
    new_symmetric_key(_session->_call->_key_local);

    _session->_call->_nonce_local = calloc( sizeof(uint8_t), crypto_box_NONCEBYTES );
    new_nonce(_session->_call->_nonce_local);

    /* Save peer key/nonce */
    _session->_call->_key_peer = calloc( sizeof(uint8_t), crypto_secretbox_KEYBYTES );
    memcpy(_session->_call->_key_peer, _msg->_cryptokey._header_value, crypto_secretbox_KEYBYTES);

    _session->_call->_nonce_peer = calloc( sizeof(uint8_t), crypto_box_NONCEBYTES );
    memcpy(_session->_call->_nonce_peer, _msg->_nonce._header_value,  crypto_box_NONCEBYTES);

    _session->_call->_state = call_active;

    msi_msg_t* _msg_start = msi_msg_new ( TYPE_REQUEST, stringify_request ( _start ) );
    msi_msg_set_cryptokey(_msg_start, _session->_call->_key_local, crypto_secretbox_KEYBYTES);
    msi_msg_set_nonce(_msg_start, _session->_call->_nonce_local, crypto_box_NONCEBYTES);
    msi_send_msg ( _session, _msg_start );
    msi_msg_free ( _msg_start );

    flush_peer_type ( _session, _msg, 0 );

    event.throw(msi_callback[cb_starting], _session);
    event.timer_release( _session->_call->_ringing_timer_id );

    return 1;
}
int msi_handle_recv_ending ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;


    msi_terminate_call ( _session );

    event.throw(msi_callback[cb_ending], _session);

    return 1;
}
int msi_handle_recv_error ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);
    assert(_session->_call);

    /* Handle error accordingly */
    if ( _msg->_reason._header_value ) {
        _session->_last_error_id = atoi((const char*)_msg->_reason._header_value);
        _session->_last_error_str = stringify_error(_session->_last_error_id);
    }

    msi_terminate_call(_session);

    event.throw(msi_callback[cb_ending], _session);

    return 1;
}

/*********************************************************/


/********** Action handlers **********/

int msi_invite ( msi_session_t* _session, call_type _call_type, uint32_t _rngsec )
{
    assert(_session);

    if ( !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_invite = msi_msg_new ( TYPE_REQUEST, stringify_request ( _invite ) );

    _session->_call = msi_init_call ( _session, 1, _rngsec ); /* Just one for now */
    t_randomstr(_session->_call->_id, _CALL_ID_LEN);

    _session->_call->_type_local = _call_type;
    /* Do whatever with message */

    if ( _call_type == type_audio ) {
        msi_msg_set_calltype
            ( _msg_invite, ( const uint8_t* ) CT_AUDIO_HEADER_VALUE, strlen(CT_AUDIO_HEADER_VALUE) );
    } else {
        msi_msg_set_calltype
            ( _msg_invite, ( const uint8_t* ) CT_VIDEO_HEADER_VALUE, strlen(CT_VIDEO_HEADER_VALUE) );
    }

    msi_send_msg ( _session, _msg_invite );
    msi_msg_free ( _msg_invite );

    _session->_call->_state = call_inviting;

    _session->_call->_request_timer_id = event.timer_alloc(msi_handle_timeout, _session, m_deftout);

    return 1;
}
int msi_hangup ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call || ( !msi_send_message_callback && _session->_call->_state != call_active ) )
        return 0;

    msi_msg_t* _msg_ending = msi_msg_new ( TYPE_REQUEST, stringify_request ( _end ) );
    msi_send_msg ( _session, _msg_ending );
    msi_msg_free ( _msg_ending );

    _session->_call->_request_timer_id = event.timer_alloc(msi_handle_timeout, _session, m_deftout);

    return 1;
}
int msi_answer ( msi_session_t* _session, call_type _call_type )
{
    assert(_session);

    if ( !msi_send_message_callback || !_session->_call )
        return 0;

    msi_msg_t* _msg_starting = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _starting ) );
    _session->_call->_type_local = _call_type;

    if ( _call_type == type_audio ) {
        msi_msg_set_calltype
            ( _msg_starting, ( const uint8_t* ) CT_AUDIO_HEADER_VALUE, strlen(CT_AUDIO_HEADER_VALUE) );
    } else {
        msi_msg_set_calltype
            ( _msg_starting, ( const uint8_t* ) CT_VIDEO_HEADER_VALUE, strlen(CT_VIDEO_HEADER_VALUE) );
    }

    /* Now set the local encryption key and pass it with STARTING message */

    _session->_call->_key_local = calloc( sizeof(uint8_t), crypto_secretbox_KEYBYTES );
    new_symmetric_key(_session->_call->_key_local);

    _session->_call->_nonce_local = calloc( sizeof(uint8_t), crypto_box_NONCEBYTES );
    new_nonce(_session->_call->_nonce_local);

    msi_msg_set_cryptokey(_msg_starting, _session->_call->_key_local, crypto_secretbox_KEYBYTES);
    msi_msg_set_nonce(_msg_starting, _session->_call->_nonce_local, crypto_box_NONCEBYTES);

    msi_send_msg ( _session, _msg_starting );
    msi_msg_free ( _msg_starting );

    _session->_call->_state = call_active;

    return 1;
}
int msi_cancel ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call || !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_cancel = msi_msg_new ( TYPE_REQUEST, stringify_request ( _cancel ) );
    msi_send_msg ( _session, _msg_cancel );
    msi_msg_free ( _msg_cancel );

    msi_terminate_call(_session);

    return 1;
}
int msi_reject ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call || !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_reject = msi_msg_new ( TYPE_REQUEST, stringify_request ( _reject ) );
    msi_send_msg ( _session, _msg_reject );
    msi_msg_free ( _msg_reject );

    _session->_call->_request_timer_id = event.timer_alloc(msi_handle_timeout, _session, m_deftout);

    return 1;
}
int msi_stopcall ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call )
        return 0;

    /* just terminate it */

    msi_terminate_call(_session);

    return 1;
}

/*********************************************************/


/**
 * OUR MAIN POOL FUNCTION
 * Forks it self to other thread and then handles the session initiation.
 *
 * BASIC call flow:
 *
 *    ALICE                    BOB
 *      | invite -->            |
 *      |                       |
 *      |           <-- ringing |
 *      |                       |
 *      |          <-- starting |
 *      |                       |
 *      | start -->             |
 *      |                       |
 *      |  <-- MEDIA TRANS -->  |
 *      |                       |
 *      | end -->               |
 *      |                       |
 *      |            <-- ending |
 *
 * Alice calls Bob by sending invite packet.
 * Bob recvs the packet and sends an ringing packet;
 * which notifies Alice that her invite is acknowledged.
 * Ringing screen shown on both sides.
 * Bob accepts the invite for a call by sending starting packet.
 * Alice recvs the starting packet and sends the started packet to
 * inform Bob that she recved the starting packet.
 * Now the media transmission is established ( i.e. RTP transmission ).
 * Alice hangs up and sends end packet.
 * Bob recves the end packet and sends ending packet
 * as the acknowledgement that the call is ending.
 *
 *
 */

void* msi_poll_stack ( void* _session_p )
{
    msi_session_t* _session = ( msi_session_t* ) _session_p;
    msi_msg_t*     _msg = NULL;

    uint32_t* _frequ =  &_session->_frequ;
    while ( _session->_running ) {

        /* At this point it's already parsed */
        _msg = receive_message ( _session );

        if ( _msg ) {

            if ( _msg->_request._header_value ) { /* Handle request */

                const uint8_t* _request_value = _msg->_request._header_value;

                if ( same ( _request_value, stringify_request ( _invite ) ) ) {
                    msi_handle_recv_invite ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _start ) ) ) {
                    msi_handle_recv_start ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _cancel ) ) ) {
                    msi_handle_recv_cancel ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _reject ) ) ) {
                    msi_handle_recv_reject ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _end ) ) ) {
                    msi_handle_recv_end ( _session, _msg );
                }

            } else if ( _msg->_response._header_value ) { /* Handle response */

                const uint8_t* _response_value = _msg->_response._header_value;

                if ( same ( _response_value, stringify_response ( _ringing ) ) ) {
                    msi_handle_recv_ringing ( _session, _msg );

                } else if ( same ( _response_value, stringify_response ( _starting ) ) ) {
                    msi_handle_recv_starting ( _session, _msg );

                } else if ( same ( _response_value, stringify_response ( _ending ) ) ) {
                    msi_handle_recv_ending ( _session, _msg );

                } else if ( same ( _response_value, stringify_response ( _error ) ) ) {
                    msi_handle_recv_error ( _session, _msg );
                }
                else {
                    msi_msg_free(_msg);
                    continue;
                }

                /* Got response so cancel timer */
                if ( _session->_call )
                    event.timer_release(_session->_call->_request_timer_id);

            }

            msi_msg_free ( _msg );

        }
        usleep ( *_frequ );
    }

    _session->_running = -1;

    pthread_exit(NULL);;
}

/*********************************************************/
