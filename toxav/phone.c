#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define _BSD_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>

#include "toxmsi.h"
#include "toxrtp.h"
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include "../toxcore/network.h"
#include "../toxcore/event.h"

/* Define client version */
#define _USERAGENT "v.0.3.0"

typedef struct av_session_s {
    msi_session_t* _msi;

    rtp_session_t* _rtp_audio;
    rtp_session_t* _rtp_video;

    uint16_t _send_port, _recv_port;

    pthread_mutex_t _mutex;

    Networking_Core* _networking;
} av_session_t;


int t_setipport ( const char* _ip, unsigned short _port, void* _dest )
{
    assert(_dest);

    IP_Port* _dest_c = ( IP_Port* ) _dest;
    ip_init(&_dest_c->ip, 0);

    IP_Port _ipv6_garbage;

    if ( !addr_resolve(_ip, &_dest_c->ip, &_ipv6_garbage.ip) )
        return -1;

    _dest_c->port = htons ( _port );

    return 0;
}

void INFO (const char* _format, ...)
{
    printf("\r[!] ");
    va_list _arg;
    va_start (_arg, _format);
    vfprintf (stdout, _format, _arg);
    va_end (_arg);
    printf("\n\r >> ");
    fflush(stdout);
}

void* phone_receivepacket ( void* _phone_p )
{
    av_session_t* _phone = _phone_p;

    /* Now start main networking loop */
    while ( _phone->_networking ) { /* so not thread safe */
        networking_poll(_phone->_networking);
        usleep(10000);
    }

    pthread_exit ( NULL );
}

void* phone_handle_media_transport_poll ( void* _hmtc_args_p )
{
    rtp_msg_t* _audio_msg, * _video_msg;
    av_session_t* _phone = _hmtc_args_p;
    msi_session_t* _session = _phone->_msi;

    rtp_session_t* _rtp_audio = _phone->_rtp_audio;
    rtp_session_t* _rtp_video = _phone->_rtp_video;

    void* _core_handler = _phone->_msi->_net_core;

    while ( _session->_call ) {

        _audio_msg = rtp_recv_msg ( _rtp_audio );
        _video_msg = rtp_recv_msg ( _rtp_video );

        if ( _audio_msg ) {
            /* Do whatever with msg*/
            puts(_audio_msg->_data);
            rtp_free_msg ( _rtp_audio, _audio_msg );
        }

        if ( _video_msg ) {
            /* Do whatever with msg*/
            puts(_video_msg->_data);
            rtp_free_msg ( _rtp_video, _video_msg );
        }
        /* -------------------- */

        /*
         * Make a test msg and send that message to the 'remote'
         */
        _audio_msg = rtp_msg_new ( _rtp_audio, (const uint8_t*)"audio\0", 6 ) ;
        rtp_send_msg ( _rtp_audio, _audio_msg, _core_handler );

        if ( _session->_call->_type_local == type_video ){ /* if local call send video */
            _video_msg = rtp_msg_new ( _rtp_video, (const uint8_t*)"video\0", 6 ) ;
            rtp_send_msg ( _rtp_video, _video_msg, _core_handler );
        }

        /*THREADUNLOCK()*/

        usleep ( 10000 );
        /* -------------------- */
    }

    /*THREADLOCK()*/

    if ( _audio_msg ){
        rtp_free_msg(_rtp_audio, _audio_msg);
    }

    if ( _video_msg ) {
        rtp_free_msg(_rtp_video, _video_msg);
    }

    rtp_release_session_recv(_rtp_video);
    rtp_release_session_recv(_rtp_audio);

    rtp_terminate_session(_rtp_audio);
    rtp_terminate_session(_rtp_video);

    /*THREADUNLOCK()*/

    INFO("Media thread finished!");

    pthread_exit ( NULL );
}

int phone_startmedia_loop ( av_session_t* _phone )
{
    if ( !_phone ){
        return -1;
    }

    int _status;
    pthread_t _rtp_tid;


    _phone->_rtp_audio = rtp_init_session ( _phone->_networking, type_audio );

    _phone->_rtp_audio->_dest = _phone->_msi->_friend_id;

    _phone->_rtp_audio->_decrypt_key = _phone->_msi->_call->_key_local;
    _phone->_rtp_audio->_encrypt_key = _phone->_msi->_call->_key_peer;

    _phone->_rtp_audio->_decrypt_nonce = _phone->_msi->_call->_nonce_local;
    _phone->_rtp_audio->_encrypt_nonce = _phone->_msi->_call->_nonce_peer;

    rtp_set_payload_type(_phone->_rtp_audio, _PAYLOAD_OPUS);


    _phone->_rtp_video = rtp_init_session ( _phone->_networking, type_video );

    _phone->_rtp_video->_dest = _phone->_msi->_friend_id;
    _phone->_rtp_video->_decrypt_key = _phone->_msi->_call->_key_local;
    _phone->_rtp_video->_encrypt_key = _phone->_msi->_call->_key_peer;

    _phone->_rtp_video->_decrypt_nonce = _phone->_msi->_call->_nonce_local;
    _phone->_rtp_video->_encrypt_nonce = _phone->_msi->_call->_nonce_peer;

    rtp_set_payload_type(_phone->_rtp_video, _PAYLOAD_VP8);


    if ( 0 > event.throw(phone_handle_media_transport_poll, _phone) )
    {
        printf("Error while starting phone_handle_media_transport_poll()\n");
        return -1;
    }
    else return 0;
}


/* Some example callbacks */

void callback_recv_invite ( void* _arg )
{
    const char* _call_type;

    msi_session_t* _msi = _arg;

    switch ( _msi->_call->_type_peer[_msi->_call->_participants - 1] ){
    case type_audio:
        _call_type = "audio";
        break;
    case type_video:
        _call_type = "video";
        break;
    }

    INFO( "Incoming %s call!", _call_type );

}
void callback_recv_trying ( void* _arg )
{
    INFO ( "Trying...");
}
void callback_recv_ringing ( void* _arg )
{
    INFO ( "Ringing!" );
}
void callback_recv_starting ( void* _arg )
{
    msi_session_t* _session = _arg;
    if ( 0 != phone_startmedia_loop(_session->_agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }
}
void callback_recv_ending ( void* _arg )
{
    INFO ( "Call ended!" );
}

void callback_recv_error ( void* _arg )
{
    msi_session_t* _session = _arg;

    INFO( "Error: %s", _session->_last_error_str );
}

void callback_call_started ( void* _arg )
{
    msi_session_t* _session = _arg;
    if ( 0 != phone_startmedia_loop(_session->_agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }

}
void callback_call_canceled ( void* _arg )
{
    INFO ( "Call canceled!" );
}
void callback_call_rejected ( void* _arg )
{
    INFO ( "Call rejected!\n" );
}
void callback_call_ended ( void* _arg )
{
    INFO ( "Call ended!" );
}

void callback_requ_timeout ( void* _arg )
{
    INFO( "No answer! " );
}


av_session_t* av_init_session(uint16_t _listen_port, uint16_t _send_port)
{
    av_session_t* _retu = malloc(sizeof(av_session_t));

    /* Initialize our mutex */
    pthread_mutex_init ( &_retu->_mutex, NULL );

    IP_Port _local;
    ip_init(&_local.ip, 0);
    _local.ip.ip4.uint32 = htonl ( INADDR_ANY );

    /* Bind local receive port to any address */
    _retu->_networking = new_networking ( _local.ip, _listen_port );

    if ( !_retu->_networking ) {
        fprintf ( stderr, "new_networking() failed!\n" );
        return NULL;
    }

    _retu->_send_port = _send_port;
    _retu->_recv_port = _listen_port;

    _retu->_rtp_audio = NULL;
    _retu->_rtp_video = NULL;


    /* Initialize msi */
    _retu->_msi = msi_init_session ( _retu->_networking, (const uint8_t*)_USERAGENT );

    if ( !_retu->_msi ) {
        fprintf ( stderr, "msi_init_session() failed\n" );
        return NULL;
    }


    _retu->_msi->_agent_handler = _retu;
    /* Initiate callbacks */
    msi_register_callback_send ( sendpacket ); /* Using core's send */

    msi_register_callback(callback_call_started, cb_onstart);
    msi_register_callback(callback_call_canceled, cb_oncancel);
    msi_register_callback(callback_call_rejected, cb_onreject);
    msi_register_callback(callback_call_ended, cb_onend);
    msi_register_callback(callback_recv_invite, cb_oninvite);

    msi_register_callback(callback_recv_ringing, cb_ringing);
    msi_register_callback(callback_recv_starting, cb_starting);
    msi_register_callback(callback_recv_ending, cb_ending);

    msi_register_callback(callback_recv_error, cb_error);
    msi_register_callback(callback_requ_timeout, cb_timeout);
    /* ------------------ */

    return _retu;
}

void* phone_poll ( void* _p_phone )
{
    av_session_t* _phone = _p_phone;

    int _status = 0;

    char* _line;
    size_t _len;


    char _dest[17]; /* For parsing destination ip */
    memset(_dest, '\0', 17);

    INFO("Welcome to tox_phone version: " _USERAGENT "\n"
         "Usage: \n"
         "c [a/v] (type) [0.0.0.0] (dest ip) (calls dest ip)\n"
         "h (if call is active hang up)\n"
         "a [a/v] (answer incoming call: a - audio / v - audio + video (audio is default))\n"
         "r (reject incoming call)\n"
         "q (quit)\n"
         "================================================================================"
         );

    while ( 1 )
    {
        getline(&_line, &_len, stdin);

        if ( !_len ){
            printf(" >> "); fflush(stdout);
            continue;
        }

        if ( _len > 1 && _line[1] != ' ' && _line[1] != '\n' ){
            INFO("Invalid input!");
            continue;
        }

        switch (_line[0]){

        case 'c':
        {
            if ( _phone->_msi->_call ){
                INFO("Already in a call");
                break;
            }

            call_type _ctype;
            if ( _len < 11 ){
                INFO("Invalid input; usage: c a/v 0.0.0.0");
                break;
            }
            else if ( _line[2] == 'a' || _line[2] != 'v' ){ /* default and audio */
                _ctype = type_audio;
            }
            else { /* video */
                _ctype = type_video;
            }

            strcpy(_dest, _line + 4 );
            _status = t_setipport(_dest, _phone->_send_port, &(_phone->_msi->_friend_id));

            if ( _status < 0 ){
                INFO("Could not resolve address!");
            } else {
                /* Set timeout */
                msi_invite ( _phone->_msi, _ctype, 10 * 1000 );
                INFO("Calling!");
            }

            memset((uint8_t*)_dest, '\0', 17);

        } break;
        case 'h':
        {
            if ( !_phone->_msi->_call ){
                INFO("No call!");
                break;
            }

            msi_hangup(_phone->_msi);

            INFO("Hung up...");

        } break;
        case 'a':
        {

            if ( _phone->_msi->_call && _phone->_msi->_call->_state != call_starting ) {
                break;
            }

            if ( _len > 1 && _line[2] == 'v' )
                msi_answer(_phone->_msi, type_video);
            else
                msi_answer(_phone->_msi, type_audio);

        } break;
        case 'r':
        {
            if ( _phone->_msi->_call && _phone->_msi->_call->_state != call_starting ){
                break;
            }

            msi_reject(_phone->_msi);

            INFO("Call Rejected...");

        } break;
        case 'q':
        {
            INFO("Quitting!");
            pthread_exit(NULL);
        }
        default:
        {
            INFO("Invalid command!");
        } break;

        }

    }

    pthread_exit(NULL);
}

pthread_t phone_startmain_loop(av_session_t* _phone)
{
    int _status;
    /* Start receive thread */
    pthread_t _recv_thread, _phone_loop_thread;
    _status = pthread_create ( &_recv_thread, NULL, phone_receivepacket, _phone );

    if ( _status < 0 ) {
        printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    _status = pthread_detach ( _recv_thread );

    if ( _status < 0 ) {
        printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    _status = pthread_create ( &_phone_loop_thread, NULL, phone_poll, _phone );

    if ( _status < 0 ) {
        printf ( "Error while starting main phone loop: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    _status = pthread_join ( _phone_loop_thread, NULL );

    if ( _status < 0 ) {
        printf ( "Error while starting main phone loop: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    return _phone_loop_thread;
}

int av_terminate_session(av_session_t* _phone)
{
    if ( _phone->_msi->_call ){
        msi_hangup(_phone->_msi); /* Hangup the phone first */
    }

    msi_terminate_session(_phone->_msi);
    pthread_mutex_destroy ( &_phone->_mutex );

    printf("\r[i] Quit!\n");
    return 0;
}

/* ---------------------- */

int print_help ( const char* _name )
{
    printf ( "Usage: %s -m (mode) -r/s ( for setting the ports on test version )\n", _name );
    return -1;
}

int main ( int argc, char* argv [] )
{
    if ( argc < 1 )
        return 1;

    const char* _mode = argv[1];

    uint16_t _listen_port;
    uint16_t _send_port;

    if ( _mode[0] == 'r' ) {
        _send_port = 31000;
        _listen_port = 31001;
    } else if ( _mode[0] == 's' ) {
        _send_port = 31001;
        _listen_port = 31000;
    } else return print_help ( argv[0] );

    av_session_t* _phone = av_init_session(_listen_port, _send_port);

    if ( _phone ){
        phone_startmain_loop(_phone);

        av_terminate_session(_phone);
    }

    return 0;
}
