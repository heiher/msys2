/*
 * Copyright (c) 2011 Mark Heily <mark@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "../common/private.h"

static VOID CALLBACK
evfilt_read_callback(void *param, BOOLEAN fired)
{
    WSANETWORKEVENTS events;
    struct kqueue *kq;
    struct knote *kn;
    int rv;

    assert(param);

    if (fired) {
        dbg_puts("called, but event was not triggered(?)");
        return;
    }

    assert(param);
    kn = (struct knote*)param;
    // FIXME: check if knote is pending destroyed
    kq = kn->kn_kq;
    assert(kq);

    /* Retrieve the socket events and update the knote */
    rv = WSAEnumNetworkEvents(
            (SOCKET) kn->kev.ident,
            kn->kn_handle,
                &events);
    if (rv != 0) {
        dbg_wsalasterror("WSAEnumNetworkEvents");
        return; //fIXME: should crash or invalidate the knote
    }

    knote_retain(kn);
    if (!PostQueuedCompletionStatus(kq->kq_iocp, 1, (ULONG_PTR) 0, (LPOVERLAPPED) param)) {
        dbg_lasterror("PostQueuedCompletionStatus()");
        knote_release(kn);
        return;
    }
}

int
evfilt_rw_copyout(struct kevent *dst, UNUSED int nevents, struct filter *filt,
    struct knote *src, void *ptr)
{
    unsigned long bufsize;
    int res = -1;

    if (src->kn_handle) {
        memcpy(dst, &src->kev, sizeof(*dst));
        dst->data = 1;

        if (knote_copyout_flag_actions(filt, src) >= 0)
            res = 1;
    }

    knote_release(src);
    return res;
}

static struct knote *
evfilt_rw_knote_lookup_pair(struct filter *filt, struct knote *kn)
{
    struct filter *filtp;
    struct knote *knp;
    int id;

    id = (filt->kf_id == EVFILT_READ) ? EVFILT_WRITE : EVFILT_READ;
    if (filter_lookup(&filtp, kn->kn_kq, id) < 0)
        return NULL;

    return knote_lookup(filtp, kn->kev.ident);
}

static long
evfilt_rw_events(struct filter *filt, struct knote *knp)
{
    static long filt_events[2] = { FD_READ | FD_ACCEPT, FD_WRITE | FD_CONNECT };
    long events = FD_CLOSE;

    events |= filt_events[~filt->kf_id];
    if (knp) {
        int id = (filt->kf_id == EVFILT_READ) ? EVFILT_WRITE : EVFILT_READ;
        events |= filt_events[~id];
    }

    return events;
}

int
evfilt_rw_knote_create(struct filter *filt, struct knote *kn)
{
    struct knote *knp;
    HANDLE evt;
    int rv;

    if (windows_get_descriptor_type(kn) < 0)
        return (-1);

    knp = evfilt_rw_knote_lookup_pair(filt, kn);

    if (knp && knp->kn_handle) {
        evt = knp->kn_handle;
    } else {
        /* Create an auto-reset event object */
        evt = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (evt == NULL) {
            dbg_lasterror("CreateEvent()");
            return (-1);
        }
    }

    rv = WSAEventSelect(
                (SOCKET) kn->kev.ident,
                evt,
                evfilt_rw_events(filt, knp));
    if (rv != 0) {
        dbg_wsalasterror("WSAEventSelect()");
        CloseHandle(evt);
        return (-1);
    }

    kn->kn_handle = evt;

    if (knp && knp->kn_event_whandle) {
        kn->kn_event_whandle = knp->kn_event_whandle;
    } else {
        if (RegisterWaitForSingleObject(&kn->kn_event_whandle, evt,
            evfilt_read_callback, kn, INFINITE, 0) == 0) {
            dbg_puts("RegisterWaitForSingleObject failed");
            CloseHandle(evt);
            return (-1);
        }
    }

    knote_retain(kn);

    return (0);
}

int
evfilt_rw_knote_modify(struct filter *filt, struct knote *kn,
        const struct kevent *kev)
{
    struct knote *knp;
    int rv;

    if (kn->kn_handle == NULL)
        return (-1);

    knp = evfilt_rw_knote_lookup_pair(filt, kn);

    rv = WSAEventSelect(
                (SOCKET) kn->kev.ident,
                kn->kn_handle,
                evfilt_rw_events(filt, knp));
    if (rv != 0) {
        dbg_wsalasterror("WSAEventSelect()");
        return (-1);
    }

    return 0;
}

int
evfilt_rw_knote_delete(struct filter *filt, struct knote *kn)
{
    struct knote *knp;

    if (kn->kn_handle == NULL || kn->kn_event_whandle == NULL)
        return (0);

    knp = evfilt_rw_knote_lookup_pair(filt, kn);

    if(!UnregisterWaitEx(kn->kn_event_whandle, INVALID_HANDLE_VALUE)) {
        dbg_lasterror("UnregisterWait()");
        return (-1);
    }

    if (knp && knp->kn_handle) {
        if (RegisterWaitForSingleObject(&knp->kn_event_whandle, knp->kn_handle,
            evfilt_read_callback, knp, INFINITE, 0) == 0) {
            dbg_puts("RegisterWaitForSingleObject failed");
            return (-1);
        }
    } else {
        if (!WSACloseEvent(kn->kn_handle)) {
            dbg_wsalasterror("WSACloseEvent()");
            return (-1);
        }
    }

    kn->kn_event_whandle = NULL;
    kn->kn_handle = NULL;
    knote_release(kn);
    return (0);
}

int
evfilt_rw_knote_enable(struct filter *filt, struct knote *kn)
{
    return evfilt_rw_knote_create(filt, kn);
}

int
evfilt_rw_knote_disable(struct filter *filt, struct knote *kn)
{
    return evfilt_rw_knote_delete(filt, kn);
}

const struct filter evfilt_read = {
    .kf_id      = EVFILT_READ,
    .kf_copyout = evfilt_rw_copyout,
    .kn_create  = evfilt_rw_knote_create,
    .kn_modify  = evfilt_rw_knote_modify,
    .kn_delete  = evfilt_rw_knote_delete,
    .kn_enable  = evfilt_rw_knote_enable,
    .kn_disable = evfilt_rw_knote_disable,
};

const struct filter evfilt_write = {
    .kf_id      = EVFILT_WRITE,
    .kf_copyout = evfilt_rw_copyout,
    .kn_create  = evfilt_rw_knote_create,
    .kn_modify  = evfilt_rw_knote_modify,
    .kn_delete  = evfilt_rw_knote_delete,
    .kn_enable  = evfilt_rw_knote_enable,
    .kn_disable = evfilt_rw_knote_disable,
};
