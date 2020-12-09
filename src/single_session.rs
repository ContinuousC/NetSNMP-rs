/****************************************************************************** 
 * Copyright 2025 ContinuousC                                                 * 
 *                                                                            * 
 * Licensed under the Apache License,  Version 2.0  (the "License");  you may * 
 * not use this file except in compliance with the License. You may  obtain a * 
 * copy of the License at http://www.apache.org/licenses/LICENSE-2.0          * 
 *                                                                            * 
 * Unless  required  by  applicable  law  or agreed  to in  writing, software * 
 * distributed under the License is distributed on an "AS IS"  BASIS, WITHOUT * 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express  or implied.  See the * 
 * License for the  specific language  governing permissions  and limitations * 
 * under the License.                                                         * 
 ******************************************************************************/

use std::convert::TryFrom;
use std::ffi::CStr;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::RawFd;
use std::pin::{pin, Pin};
use std::task::{Context, Poll};
use std::time::Duration;
use std::{fmt, mem};

use pin_project::pin_project;
use tokio::io::unix::AsyncFd;
use tokio::time::Sleep;
//use mio::unix::SourceFd;
//use mio::Ready;

use super::api;
use super::callback_op::CallbackOp;
use super::error::{Error, Result};
use super::msg::Msg;
use super::oid::Oid;
use super::pdu::{Pdu, PduPtr};
use super::session::{SessionInfo, SessionPtr, SyncQuery};
use super::transport::TransportPtr;
use super::variable::{Variable, VariablePtr};

/// An owned, heap allocated open session opened via the single session API (seems to be thread safe).
pub struct SingleSession(*mut api::session_list);

/// A smart pointer to a session opened via the single session API (seems to be thread safe).
pub struct SingleSessionPtr(api::session_list);

/// Sessions using the single session API are officially thread-safe
/// for SNMPv2c, but seem to be thread-safe for SNMPv3 as well.
unsafe impl Send for SingleSession {}

/// Sessions using the single session API are officially thread-safe
/// for SNMPv2c, but seem to be thread-safe for SNMPv3 as well.
unsafe impl Send for SingleSessionPtr {}

/// Future returned from async fns on single session.
#[pin_project]
pub struct SessionRead<'a> {
    session: &'a mut SingleSessionPtr,
    readable: AsyncFd<RawFd>,
    #[pin]
    timeout: Sleep,
}

/// Future to wait for session to become writable.
// pub struct SessionWrite<'a> {
//     _session: &'a mut SingleSessionPtr,
//     writable: AsyncFd<RawFd>,
// }

impl SingleSession {
    pub unsafe fn from_raw(ptr: *mut api::session_list) -> Self {
        Self(ptr)
    }

    pub fn into_raw(self) -> *mut api::session_list {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }
}

impl SingleSessionPtr {
    pub unsafe fn from_ptr<'a>(ptr: *const api::session_list) -> &'a Self {
        &*(ptr as *const Self)
    }

    pub unsafe fn from_mut<'a>(ptr: *mut api::session_list) -> &'a mut Self {
        &mut *(ptr as *mut Self)
    }

    pub fn as_raw(&self) -> *const api::session_list {
        &self.0 as *const api::session_list
    }

    pub fn transport(&self) -> &TransportPtr {
        unsafe {
            TransportPtr::from_ptr(api::snmp_sess_transport(
                &self.0 as *const api::session_list as *mut api::session_list,
            ))
        }
    }

    pub fn set_async_probe(&mut self, val: bool) {
        let flags = &mut (*self.session_mut()).0.flags;
        match val {
            true => *flags |= api::SNMP_FLAGS_DONT_PROBE as u64,
            false => *flags &= !api::SNMP_FLAGS_DONT_PROBE as u64,
        }
    }

    /* Asynchronous queries. */

    pub async fn get_async(&mut self, oid: &Oid) -> Result<Option<Variable>> {
        let pdu = Pdu::get().add_oid(oid);
        Ok(self
            .async_response(pdu)
            .await?
            .variables()
            .next()
            .map(VariablePtr::to_owned))
    }

    pub async fn get_next_async(&mut self, oid: &Oid) -> Result<Option<Variable>> {
        let pdu = Pdu::get().add_oid(oid);
        Ok(self
            .async_response(pdu)
            .await?
            .variables()
            .next()
            .map(VariablePtr::to_owned))
    }

    pub async fn get_bulk_async(
        &mut self,
        gets: &[Oid],
        walks: &[Oid],
        repetitions: usize,
    ) -> Result<Pdu> {
        let mut pdu = Pdu::get_bulk(gets.len() as i64, repetitions as i64);
        for oid in gets {
            pdu = pdu.add_oid(oid);
        }
        for oid in walks {
            pdu = pdu.add_oid(oid);
        }
        self.async_response(pdu).await
    }

    pub async fn get_many_async(&mut self, oids: &[Oid]) -> Result<Pdu> {
        let mut pdu = Pdu::get_bulk(oids.len() as i64, 1);
        for oid in oids {
            pdu = pdu.add_oid(oid);
        }
        self.async_response(pdu).await
    }

    pub async fn async_response(&mut self, mut pdu: Pdu) -> Result<Pdu> {
        if unsafe {
            (*self.session()).0.flags & api::SNMP_FLAGS_DONT_PROBE as u64 != 0
                && api::snmp_sess_needs_probe(&mut self.0, pdu.as_mut()) != 0
        } {
            self.writable().await;

            if unsafe { api::snmp_sess_send_probe(&mut self.0) == 0 } {
                self.set_async_probe(true);
                return Err(Error::General(String::from("Engineid probe failed.")));
            }

            let (status, response) = match self.read().await {
                Ok(pdu) => match pdu.command() {
                    Ok(Msg::Report) => (api::STAT_ERROR as i32, std::ptr::null_mut()),
                    _ => (api::STAT_SUCCESS as i32, pdu.into_raw()),
                },
                Err(_) => (api::STAT_TIMEOUT as i32, std::ptr::null_mut()),
            };

            if unsafe {
                api::snmp_sess_process_probe_response(&mut self.0, status, response)
                    != api::SNMPERR_SUCCESS as i32
            } {
                self.set_async_probe(true);
                return Err(Error::General(String::from("Engineid probe failed.")));
            }

            /* This is disabled after probe... */
            self.set_async_probe(true);
        }

        self.writable().await;
        self.send(pdu)?;
        self.read().await
    }

    fn select_info(&mut self) -> (i32, Duration) {
        unsafe {
            let mut nfds = 0;
            let mut block = 0;
            let mut timeout: api::timeval = mem::zeroed();
            let mut fds: api::netsnmp_large_fd_set = mem::zeroed();
            let _nsess = api::snmp_sess_select_info2(
                &mut self.0,
                &mut nfds,
                &mut fds,
                &mut timeout,
                &mut block,
            );
            api::netsnmp_large_fd_set_cleanup(&mut fds);
            /*for i in 0..(readfds.lfs_setsize as usize) {
            for j in 0..1024 {
                if (*readfds.lfs_setptr.add(i)).fds_bits[j >> 6] & (1 << (j & 0x3f)) > 0 {
                        return i as i32 * 1024 + j as i32;
                    }
                }
            }*/

            /* This is most probably correct and is much more efficient
             * than the above using the official API. */

            return (
                self.transport().socket_fd(),
                Duration::from_secs(timeout.tv_sec as u64)
                    + Duration::from_micros(timeout.tv_usec as u64),
            );
        }
    }

    pub async fn read(&mut self) -> Result<Pdu> {
        let mut result: Option<Result<Pdu>> = None;
        self.session_mut().0.callback = Some(SingleSessionPtr::async_read_callback);
        self.session_mut().0.callback_magic =
            &mut result as *mut Option<Result<Pdu>> as *mut c_void;
        let fd = AsyncFd::new(self.transport().socket_fd()).unwrap();

        loop {
            let (_, timeout) = self.select_info();
            tokio::select! {
            _ = tokio::time::sleep(timeout) => self.check_timeout(),
            _ = fd.readable() => self.async_read()
            }
            if let Some(r) = result {
                return r;
            }

            /*let result = unsafe { Box::from_raw(self.session().0.callback_magic
                            as *mut Option<Result<Pdu>>) };
            match *result {
            Some(r) => return r,
            None => { Box::into_raw(result); }
            }*/
        }

        /* Cast to *const i32 and back to get around ref checking, so that
         * SessionRead can hold a mutable reference to the session. */
        //let fd = self.transport().socket_fd_ref() as *const i32;
        /*SessionRead {
            readable: AsyncFd::new(self.transport().socket_fd()).unwrap(),
            timeout: tokio::time::sleep(timeout),
            session: self
        }*/
    }

    pub async fn writable(&mut self) {
        let fd = self.transport().socket_fd();
        let _ = AsyncFd::new(fd).unwrap().writable().await.unwrap();
    }

    fn async_read(&mut self) {
        unsafe {
            let fd = self.transport().socket_fd(); //self.select_info();
            assert!(fd > 0, "FD < 0");
            let mut fds: api::netsnmp_large_fd_set = mem::zeroed();
            let mut set = vec![0u64; (fd as usize >> 6) + 1];
            fds.lfs_setsize = fd as u32 + 1;
            fds.lfs_setptr = &mut set[0] as *mut u64 as *mut api::fd_set;
            set[fd as usize >> 6] |= 1 << (fd & 0x3f);
            api::snmp_sess_read2(&mut self.0, &mut fds);
        }
    }

    fn check_timeout(&mut self) {
        unsafe {
            api::snmp_sess_timeout(&mut self.0);
        }
    }

    pub fn probe_engine_id(&mut self) {
        unsafe {
            let session = &self.session().0 as *const api::snmp_session as *mut api::snmp_session;
            api::snmpv3_engineID_probe(&mut self.0, session);
            (*session).flags |= api::SNMP_FLAGS_DONT_PROBE as u64;
        }
    }

    extern "C" fn async_read_callback(
        op: c_int,
        _session: *mut api::netsnmp_session,
        _reqid: c_int,
        pdu: *mut api::netsnmp_pdu,
        magic: *mut c_void,
    ) -> c_int {
        //eprintln!("SNMP callback!");
        let mut result = unsafe { Box::from_raw(magic as *mut Option<Result<Pdu>>) };
        match CallbackOp::try_from(op) {
            Ok(CallbackOp::ReceivedMessage) => unsafe {
                *result = Some(Ok(PduPtr::from_ptr(pdu).to_owned()));
            },
            Ok(CallbackOp::TimedOut) => {
                *result = Some(Err(Error::General(String::from("timeout"))));
            }
            _ => {}
        }
        let _ = Box::into_raw(result);
        1
    }
}

impl SessionRead<'_> {
    fn check_result(self: Pin<&mut Self>) -> Option<Result<Pdu>> {
        let result = unsafe {
            Box::from_raw(self.session.session().0.callback_magic as *mut Option<Result<Pdu>>)
        };
        match *result {
            Some(r) => Some(r),
            None => {
                let _ = Box::into_raw(result);
                None
            }
        }
    }
}

impl Future for SessionRead<'_> {
    type Output = Result<Pdu>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Future::poll(self.as_mut().project().timeout, cx) {
            Poll::Ready(_) => {
                self.as_mut().project().session.check_timeout();
                match self.as_mut().check_result() {
                    Some(r) => Poll::Ready(r),
                    None => {
                        let (_, timeout) = self.as_mut().project().session.select_info();
                        unsafe {
                            let unpinned_self = Pin::into_inner_unchecked(self.as_mut());
                            unpinned_self.timeout = tokio::time::sleep(timeout);
                        }
                        /* This seems to be needed to
                         * register the new timeout. */
                        self.poll(cx)
                    }
                }
            }
            _ => match self.readable.poll_read_ready(cx) {
                Poll::Ready(Ok(_r)) => {
                    //r.clear_ready();
                    self.as_mut().project().session.async_read();
                    match self.check_result() {
                        Some(r) => Poll::Ready(r),
                        None => Poll::Pending,
                    }
                }
                _ => Poll::Pending,
            },
        }
    }
}

/*impl Future for SessionWrite<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    match self.writable.poll_write_ready(cx) {
        Poll::Ready(_) => Poll::Ready(()),
        _ => Poll::Pending
    }
    }
}*/

impl SyncQuery for SingleSessionPtr {
    fn synch_response(&mut self, pdu: Pdu) -> Result<Pdu> {
        unsafe {
            let mut response = mem::zeroed();
            let status = api::snmp_sess_synch_response(&mut self.0, pdu.as_raw(), &mut response);

            if status == (api::STAT_SUCCESS as i32) {
                mem::forget(pdu);
                let res = Pdu::from_raw(response);
                if (*response).errstat == (api::SNMP_ERR_NOERROR as i64) {
                    Ok(res)
                } else {
                    let errstr = api::snmp_errstring((*response).errstat as i32);
                    Err(Error::Packet(
                        CStr::from_ptr(errstr).to_string_lossy().into_owned(),
                    ))
                }
            } else {
                Err(self.get_error())
            }
        }
    }

    fn send(&mut self, pdu: Pdu) -> Result<()> {
        unsafe {
            if api::snmp_sess_send(&mut self.0, pdu.as_raw()) != 0 {
                mem::forget(pdu);
                Ok(())
            } else {
                Err(self.get_error())
            }
        }
    }

    fn get_error(&mut self) -> Error {
        unsafe {
            let mut errstr: *mut c_char = mem::zeroed();
            api::snmp_sess_error(
                &mut self.0,
                0 as *mut i32,
                0 as *mut i32,
                &mut errstr as *mut *mut c_char,
            );
            Error::General(CStr::from_ptr(errstr).to_string_lossy().into_owned())
        }
    }
}

impl Deref for SingleSession {
    type Target = SingleSessionPtr;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.0 as *const SingleSessionPtr) }
    }
}

impl DerefMut for SingleSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.0 as *mut SingleSessionPtr) }
    }
}

impl SessionInfo for SingleSessionPtr {
    fn session(&self) -> &SessionPtr {
        unsafe {
            &*(api::snmp_sess_session(&self.0 as *const api::session_list as *mut api::session_list)
                as *const SessionPtr)
        }
    }
    fn session_mut(&mut self) -> &mut SessionPtr {
        unsafe {
            &mut *(api::snmp_sess_session(
                &self.0 as *const api::session_list as *mut api::session_list,
            ) as *mut SessionPtr)
        }
    }
}

impl fmt::Debug for SingleSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SingleSession").field(&self.0).finish()
    }
}

impl fmt::Debug for SingleSessionPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SingleSessionPtr").field(&self.0).finish()
    }
}

impl Drop for SingleSession {
    fn drop(&mut self) {
        unsafe {
            if !self.session().0.callback_magic.is_null() {
                //mem::drop(Box::from_raw((*self.0).callback_magic));
            }
            api::snmp_sess_close(self.0);
        }
    }
}
