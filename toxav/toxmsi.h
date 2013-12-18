/* msi_initiation.h
*
* Has function for session initiation along with session description.
* It follows the Tox API ( http://wiki.tox.im/index.php/Messaging_Protocol ). !Red!
*
*
* Copyright (C) 2013 Tox project All Rights Reserved.
*
* This file is part of Tox.
*
* Tox is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Tox is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Tox. If not, see <http://www.gnu.org/licenses/>.
*
*/


#ifndef _MSI_IMPL_H_
#define _MSI_IMPL_H_

#include <inttypes.h>
#include "tox.h"
#include <pthread.h>

typedef void ( *msi_callback_t ) ( void* _arg );

/* define size for call_id */
#define _CALL_ID_LEN 12

/**
 * Call type identifier. Also used as rtp callback prefix.
 */
typedef enum {
    type_audio = 70,
    type_video,
} call_type;

/**
 * Call state identifiers.
 */
typedef enum {
    call_inviting, /* when sending call invite */
    call_starting, /* when getting call invite */
    call_active,
    call_hold

} call_state;

typedef struct msi_call_s {         /* Call info structure */
    call_state  _state;
    call_type   _type_local;
    call_type*  _type_peer;         /* Support for conference starts with this */
    uint8_t     _id[_CALL_ID_LEN];  /* Random value identifying the call */

    uint8_t*    _key_local;         /* The key for encryption */
    uint8_t*    _key_peer;          /* The key for decryption */

    uint8_t*    _nonce_local;       /* Local nonce */
    uint8_t*    _nonce_peer;        /* Peer nonce  */

    uint16_t    _participants;      /* Number of participants */

    int         _ringing_tout_ms;   /* Ringing timeout in ms */

    int         _request_timer_id;  /* Timer id for outgoing request/action */
    int         _ringing_timer_id;  /* Timer id for ringing timeout */

    pthread_mutex_t _mutex;         /* It's to be assumed that call will have
                                     * seperate thread so add mutex
                                     */
} msi_call_t;

typedef struct msi_session_s {
    pthread_mutex_t _mutex;
    int _running;

    /* Call handler */
    struct msi_call_s* _call;

    /* Storage for message receiving */
    struct msi_msg_s*  _oldest_msg;
    struct msi_msg_s*  _last_msg; /* tail */

    /*int _friend_id;*/
    tox_IP_Port _friend_id;

    int             _last_error_id; /* Determine the last error */
    const uint8_t*  _last_error_str;

    const uint8_t* _user_agent;

    void* _agent_handler; /* Pointer to an object that is handling msi */
    void* _net_core;      /* Pointer to networking handler */

    uint32_t _frequ;
    uint32_t _call_timeout; /* Time of the timeout for some action to end; 0 if infinite */

} msi_session_t;

msi_session_t* msi_init_session ( void* _net_core, const uint8_t* _user_agent );
int msi_terminate_session ( msi_session_t* _session );

/* Registering callbacks */

void msi_register_callback_send ( int ( *callback ) ( void* _net_core, tox_IP_Port,  uint8_t*, uint32_t ) );

/* Callbacks that handle the states */

typedef enum {
    /* Requests */
    cb_oninvite,
    cb_onstart,
    cb_oncancel,
    cb_onreject,
    cb_onend,

    /* Responses */
    cb_ringing,
    cb_starting,
    cb_ending,

    /* Protocol */
    cb_error,
    cb_timeout,

} callbackid_t;

void msi_register_callback(msi_callback_t _callback, callbackid_t _id);
/* -------- */

/* action functions */
int msi_invite ( msi_session_t* _session, call_type _call_type, uint32_t _rngsec );
int msi_hangup ( msi_session_t* _session );

int msi_answer ( msi_session_t* _session, call_type _call_type );
int msi_cancel ( msi_session_t* _session );
int msi_reject ( msi_session_t* _session );

int msi_stopcall ( msi_session_t* _session );

int  msi_send_msg ( msi_session_t* _session, struct msi_msg_s* _msg );
void msi_store_msg ( msi_session_t* _session, struct msi_msg_s* _msg );

#endif /* _MSI_IMPL_H_ */
