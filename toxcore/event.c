
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include "event.h"

#include "util.h"

#define _BSD_SOURCE
#define _GNU_SOURCE

#include <assert.h>
#include <unistd.h>
#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>

#define RUN_IN_THREAD(func, args) \
{   pthread_t _tid; \
    pthread_create(&_tid, NULL, func, args); \
    assert( pthread_detach(_tid) == 0 ); }

#define LOCK(event_handler)   pthread_mutex_lock  (&event_handler->_mutex)
#define UNLOCK(event_handler) pthread_mutex_unlock(&event_handler->_mutex)

#define FREQUENCY 10000

typedef struct event_container_s {
    void       (*_event)(void*);
    void*      _event_args;
    unsigned   _timeout;
    long long  _id;

} event_container_t;

typedef struct event_handler_s {
    event_container_t* _timed_events;
    size_t             _timed_events_count;

    int                _running;

    pthread_mutex_t    _mutex;

} event_handler_t;

int throw_event( void (*_func)(void*), void* _arg );
int reset_timer_event ( int _id, uint32_t _timeout );
int throw_timer_event ( void (*_func)(void*), void* _arg, unsigned _timeout);
int cancel_timer_event ( int _id );
int execute_timer_event ( int _id );

struct _event event =
{
    throw_event,
    /* reset_timer_event */ NULL,
    throw_timer_event,
    cancel_timer_event,
    /*execute_timer_event*/ NULL
};

/*
 * Random functions used by this file
 */
void clear_events (event_container_t** _event_container, size_t* _counter)
{
    free(*_event_container);

    *_event_container = NULL;
    *_counter = 0;
}

int pop_id ( event_container_t** _event_container, size_t* _counter, int _id )
{
    if ( !*_event_container || !*_counter || !_id )
        return -1;

    event_container_t* _it = *_event_container;
    int i;

    for ( i = *_counter; i; -- i ){
        if ( _it->_id == _id ) { /* Hit! */
            break;
        }
        ++_it;
    }

    if ( i ) {
        for ( ; i; -- i ){ *_it = *(_it + 1); ++_it; }
        -- (*_counter);
        *_event_container = realloc(*_event_container, sizeof(event_container_t) * (*_counter)); /* resize */

        return 0;

    }

    /* not found here */

    return -1;
}

void push_event ( event_container_t** _container, size_t* _counter, void (*_func)(void*), void* _arg )
{
    (*_container) = realloc((*_container), sizeof(event_container_t) * ((*_counter) + 1));
    assert((*_container) != NULL);

    (*_container)[*_counter]._event = _func;
    (*_container)[*_counter]._event_args = _arg;
    (*_container)[*_counter]._timeout = 0;
    (*_container)[*_counter]._id = 0;

    (*_counter)++;
}

void reorder_events ( size_t _counter, event_container_t* _container, unsigned _timeout )
{
    if ( _counter > 1 ) {

        int i = _counter - 1;

        /* start from behind excluding last added member */
        event_container_t* _it = &_container[i - 1];

        event_container_t _last_added = _container[i];

        for ( ; i; --i ) {
            if ( _it->_timeout > _timeout ){
                *(_it + 1) = *_it;
                *_it = _last_added; -- _it;
            }
        }

    }
}

/* ============================================= */

/* main poll for event execution */
void* event_poll( void *_arg )
{
    event_handler_t* _m_event_handler = _arg;

    while ( _m_event_handler->_running )
    {

    LOCK(_m_event_handler);

        if ( _m_event_handler->_timed_events ){

            uint32_t _time = ((uint32_t)(current_time() / 1000));

            if ( _m_event_handler->_timed_events[0]._timeout < _time ) {

                RUN_IN_THREAD ( _m_event_handler->_timed_events[0]._event,
                               _m_event_handler->_timed_events[0]._event_args );

                pop_id(&_m_event_handler->_timed_events,
                       &_m_event_handler->_timed_events_count,
                        _m_event_handler->_timed_events[0]._id);

            }

        }

    UNLOCK(_m_event_handler);

        usleep(FREQUENCY);
    }

LOCK(_m_event_handler);

    clear_events(&_m_event_handler->_timed_events, &_m_event_handler->_timed_events_count);

UNLOCK(_m_event_handler);

    _m_event_handler->_running = -1;
    pthread_exit(NULL);
}

int throw_event( void (*_func)(void*), void* _arg )
{
    pthread_t _tid;
    int rc =
        pthread_create(&_tid, NULL, _func, _arg);

    return (0 != rc) ? rc : pthread_detach(_tid);
}

event_handler_t _event_handler;

/* Place and order array of timers */
int throw_timer_event ( void (*_func)(void*), void* _arg, unsigned _timeout)
{
    static int _unique_id = 1;

    push_event(&_event_handler._timed_events, &(_event_handler._timed_events_count), _func, _arg);

    size_t _counter = _event_handler._timed_events_count;

    _event_handler._timed_events[_counter - 1]._timeout = _timeout + ((uint32_t)(current_time() / 1000));
    _event_handler._timed_events[_counter - 1]._id = _unique_id; ++_unique_id;


    /* reorder */

    reorder_events(_counter, _event_handler._timed_events, _timeout);

    return _unique_id - 1;
}

int execute_timer_event ( int _id )
{
    int status;

LOCK((&_event_handler));
    event_container_t* _it = _event_handler._timed_events;

    int i = _event_handler._timed_events_count;

    /* Find it and execute */
    for ( ; i; i-- ) {
        if ( _it->_id == _id ) {
            RUN_IN_THREAD ( _it->_event, _it->_event_args );
            break;
        }
        ++_it;
    }

    /* Now remove it from the queue */

    if ( i ) {
        for ( ; i; -- i ){ *_it = *(_it + 1); ++_it; }
        -- _event_handler._timed_events_count;

        _event_handler._timed_events = realloc
            (_event_handler._timed_events, sizeof(event_container_t) * _event_handler._timed_events_count); /* resize */

        status = 0;

    }
    else status = -1;

UNLOCK((&_event_handler));

    return status;
}

int reset_timer_event ( int _id, uint32_t _timeout )
{
    int status;

LOCK((&_event_handler));

    event_container_t* _it = _event_handler._timed_events;

    int i = _event_handler._timed_events_count;

    /* Find it and change */
    for ( ; i; i-- ) {
        if ( _it->_id == _id ) {
            _it->_timeout = _timeout + ((uint32_t)(current_time() / 1000));
            break;
        }
        ++_it;
    }

    status = i ? -1 : 0;

UNLOCK((&_event_handler));

    return status;
}

/* Remove timer from array */
int cancel_timer_event ( int _id )
{
    return pop_id (&_event_handler._timed_events, &_event_handler._timed_events_count, _id);
}


/* Initialization and termination of event polls
 * This will be run at the beginning and the end of the program execution.
 * I think that's the best way to do it.
 */

void __attribute__((constructor)) init_event_poll ()
{
    _event_handler._timed_events = NULL;
    _event_handler._timed_events_count = 0;

    _event_handler._running = 1;

    pthread_mutex_init(&_event_handler._mutex, NULL);

    RUN_IN_THREAD(event_poll, &_event_handler);
}

void __attribute__((destructor)) terminate_event_poll()
{
    /* Shutdown thread */
    _event_handler._running = 0;
    while (_event_handler._running != -1); /* Wait for execution */

    pthread_mutex_destroy( &_event_handler._mutex );
}
