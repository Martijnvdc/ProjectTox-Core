#ifndef _MSI__EVENT_H_
#define _MSI__EVENT_H_


/*
 * - Events are, in fact, run in their own threads upon execution.
 * - Event handler is initialized at the start of the main() function
 *      and terminated at it's ending.
 * - Timers are checked for timeout every ~10000 ns.
 * - Timers can be canceled or run immediately via
 *      timer_release() or timer_now() functions.
 * - Timeout is measured in milliseconds.
 *
 * NOTE: timer_reset () and timer_now() are not tested nor usable atm
 */

extern struct _event
{
    int (*throw) (void ( *_func ) ( void* ), void* _arg);
    int (*timer_reset ) ( int _id, unsigned _timeout );
    int (*timer_alloc) (void ( *_func ) ( void* ), void* _arg, unsigned _timeout);
    int (*timer_release) (int _id);
    int (*timer_now) ( int _id );
} event;

#endif /* _MSI__EVENT_H_ */
