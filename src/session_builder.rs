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

use std::ffi::{CStr, CString};
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_char, c_void};
use std::{fmt, mem};

use super::api;
use super::error::{Error, Result};
use super::netsnmp::NetSNMP;
use super::version::Version;
//use super::callback_op::CallbackOp;
use super::auth::{Auth, V3AuthParams, V3AuthProtocol, V3Level, V3PrivParams, V3PrivProtocol};
use super::multi_session::MultiSession;
use super::session::SessionPtr;
use super::single_session::SingleSession;
use super::transport::{Transport, TransportPtr};

/// A stack-allocated, unopened session.
pub struct SessionBuilder(api::snmp_session);

impl SessionBuilder {
    pub fn new(_snmp: &NetSNMP) -> Self {
        unsafe {
            let mut session = mem::zeroed();
            api::snmp_sess_init(&mut session);
            Self(session)
        }
    }

    /* Builder-style functions to set options */

    pub fn set_peer(mut self, peer: &[u8]) -> Result<Self> {
        if !self.0.peername.is_null() {
            mem::drop(unsafe { CString::from_raw(self.0.peername) });
        }
        self.0.peername = CString::new(peer)?.into_raw();
        Ok(self)
    }

    pub fn set_port(mut self, port: u16) -> Self {
        self.0.remote_port = port;
        self
    }

    pub fn set_version(mut self, version: Version) -> Self {
        match version {
            Version::V1 => self.0.version = api::SNMP_VERSION_1 as i64,
            Version::V2c => self.0.version = api::SNMP_VERSION_2c as i64,
            Version::V3 => self.0.version = api::SNMP_VERSION_3 as i64,
        }
        self
    }

    pub fn set_auth(mut self, auth: &Auth) -> Result<Self> {
        match auth {
            Auth::V2c(params) => {
                self.0.version = api::SNMP_VERSION_2c as i64;
                let community: Box<[u8]> = Box::from(params.community.as_bytes());
                self.0.community_len = community.len();
                self.0.community = Box::into_raw(community) as *mut u8;
                Ok(self)
            }

            Auth::V3(params) => {
                self.0.version = api::SNMP_VERSION_3 as i64;
                match &params.level {
                    V3Level::NoAuthNoPriv => Ok(self),
                    V3Level::AuthNoPriv { auth } => self.set_v3_auth(auth),
                    V3Level::AuthPriv { auth, privacy } => {
                        self.set_v3_auth(auth)?.set_v3_priv(privacy)
                    }
                }
            }
        }
    }

    fn set_v3_auth(mut self, params: &V3AuthParams) -> Result<Self> {
        let user = CString::new(params.user.as_bytes())?;
        self.0.securityNameLen = user.to_bytes().len();
        self.0.securityName = user.into_raw() as *mut i8;

        self.0.securityLevel = api::SNMP_SEC_LEVEL_AUTHNOPRIV as i32;
        self.0.securityAuthKeyLen = api::USM_AUTH_KU_LEN as usize;

        match params.protocol {
            V3AuthProtocol::MD5 => {
                self.0.securityAuthProto =
                    unsafe { api::usmHMACMD5AuthProtocol.as_slice() as *const _ as *mut _ };
                self.0.securityAuthProtoLen = api::USM_AUTH_PROTO_MD5_LEN as usize;
            }
            V3AuthProtocol::SHA => {
                self.0.securityAuthProto =
                    unsafe { api::usmHMACSHA1AuthProtocol.as_slice() as *const _ as *mut _ };
                self.0.securityAuthProtoLen = api::USM_AUTH_PROTO_SHA_LEN as usize;
            }
        }

        let mut password: Box<[u8]> = Box::from(params.password.as_bytes());
        let password_len = password.len();

        if unsafe {
            api::generate_Ku(
                self.0.securityAuthProto,
                self.0.securityAuthProtoLen as u32,
                &mut password[0],
                password_len,
                &mut self.0.securityAuthKey[0] as *mut u8,
                &mut self.0.securityAuthKeyLen,
            ) != (api::SNMPERR_SUCCESS as i32)
        } {
            Err(Error::KeyError)?;
        }

        Ok(self)
    }

    fn set_v3_priv(mut self, params: &V3PrivParams) -> Result<Self> {
        self.0.securityLevel = api::SNMP_SEC_LEVEL_AUTHPRIV as i32;
        self.0.securityPrivKeyLen = api::USM_PRIV_KU_LEN as usize;

        match params.protocol {
            V3PrivProtocol::DES => {
                self.0.securityPrivProto =
                    unsafe { &api::usmDESPrivProtocol.as_slice() as *const _ as *mut _ };
                self.0.securityPrivProtoLen = api::USM_PRIV_PROTO_DES_LEN as usize;
            }
            V3PrivProtocol::AES => {
                self.0.securityPrivProto =
                    unsafe { api::usmAESPrivProtocol.as_slice() as *const _ as *mut _ };
                self.0.securityPrivProtoLen = api::USM_PRIV_PROTO_AES_LEN as usize;
            }
        }

        let mut password: Box<[u8]> = Box::from(params.password.as_bytes());
        let password_len = password.len();

        if unsafe {
            api::generate_Ku(
                self.0.securityAuthProto,
                self.0.securityAuthProtoLen as u32,
                &mut password[0],
                password_len,
                &mut self.0.securityPrivKey[0] as *mut u8,
                &mut self.0.securityPrivKeyLen,
            ) != (api::SNMPERR_SUCCESS as i32)
        } {
            Err(Error::KeyError)?;
        }

        Ok(self)
    }

    pub fn set_retries(mut self, retries: u64) -> Self {
        self.0.retries = retries as i32;
        self
    }

    pub fn set_timeout(mut self, timeout: f64) -> Self {
        self.0.timeout = (timeout * 1000000.0).round() as i64;
        self
    }

    pub fn set_async_probe(mut self, val: bool) -> Self {
        match val {
            true => self.0.flags |= api::SNMP_FLAGS_DONT_PROBE as u64,
            false => self.0.flags &= !api::SNMP_FLAGS_DONT_PROBE as u64,
        }
        self
    }

    pub fn set_callback_static(
        mut self,
        cb: unsafe extern "C" fn(
            i32,
            *mut api::snmp_session,
            i32,
            *mut api::snmp_pdu,
            *mut c_void,
        ) -> i32,
        magic: *mut c_void,
    ) -> Self {
        self.0.callback = Some(cb) as api::netsnmp_callback;
        self.0.callback_magic = magic;
        self
    }

    /*pub fn set_callback<F>(mut self, cb: F) -> Self
    where F: FnMut(CallbackOp,&mut SessionPtr,i32,&PduPtr) -> Result<()> {

    extern "C" fn trampoline<F>(op: c_int, session: *mut api::netsnmp_session,
                    reqid: c_int, pdu: *mut api::netsnmp_pdu,
                    magic: *mut c_void) -> c_int
        where F: FnMut(CallbackOp,&mut SessionPtr,i32,&PduPtr) -> Result<()> {
        let closure: &mut F = unsafe { &mut *(magic as *mut F) };
        let session = unsafe { SessionPtr::from_mut(api::snmp_sess_pointer(session)) };
        let pdu = unsafe { PduPtr::from_ptr(pdu) };

        match CallbackOp::try_from(op) {
        Ok(op) => match (*closure)(op, session, reqid, pdu) {
            Ok(()) => 1,
            Err(_) => 1
        }
        Err(_) => {
            eprintln!("Unknown callback op: {}", op);
            1
        }
        }

    }

    self.0.callback = Some(trampoline::<F>);
    self.0.callback_magic = Box::into_raw(Box::new(cb)) as *mut c_void;
    self

    }*/

    /* Actions */

    pub fn open_single(mut self) -> Result<SingleSession> {
        // the tutorial says we need to run the SOCK_STARTUP macro on windows
        let session = unsafe { api::snmp_sess_open(&mut self.0) };
        if session.is_null() {
            Err(self.get_error())
        } else {
            /* The callback closure is allocated by rust and thus not cloned
             * by snmp_open. On success, the ownership is transfered to the
             * open session, and it should therefore not be dropped at the end
             * of this function, unlike the other allocated variables in the
             * session builder. The callback closure will be dropped when the
             * session goed out of scope. */
            //self.0.callback_magic = std::ptr::null_mut();
            let mut session = unsafe { SingleSession::from_raw(session) };
            /* This is not copied fvrom the original by netsnmp. */
            session.set_async_probe(self.0.flags & api::SNMP_FLAGS_DONT_PROBE as u64 != 0);
            Ok(session)
        }
    }

    pub fn open_multi(mut self) -> Result<MultiSession> {
        // the tutorial says we need to run the SOCK_STARTUP macro on windows
        let session = unsafe { api::snmp_open(&mut self.0) };
        if session.is_null() {
            Err(self.get_error())
        } else {
            /* The callback closure is allocated by rust and thus not cloned
             * by snmp_open. On success, the ownership is transfered to the
             * open session, and it should therefore not be dropped at the end
             * of this function, unlike the other allocated variables in the
             * session builder. The callback closure will be dropped when the
             * session goed out of scope. */
            self.0.callback_magic = std::ptr::null_mut();
            Ok(unsafe { MultiSession::from_raw(session) })
        }
    }

    // TODO: lifetime of transport???
    pub fn open_with_transport<'a>(
        mut self,
        transport: Transport,
    ) -> Result<(MultiSession, &'a mut TransportPtr)> {
        let transport = unsafe { TransportPtr::from_ptr(transport.into_raw()) };
        let session = unsafe { api::snmp_add(&mut self.0, transport.as_mut_ptr(), None, None) };
        match session.is_null() {
            true => Err(self.get_error()),
            false => {
                self.0.callback_magic = std::ptr::null_mut();
                Ok((unsafe { MultiSession::from_raw(session) }, transport))
            }
        }
    }

    pub fn get_error(&mut self) -> Error {
        unsafe {
            let mut errstr: *mut c_char = mem::zeroed();
            api::snmp_error(
                &mut self.0,
                0 as *mut i32,
                0 as *mut i32,
                &mut errstr as *mut *mut c_char,
            );
            Error::General(CStr::from_ptr(errstr).to_string_lossy().into_owned())
        }
    }
}

impl Deref for SessionBuilder {
    type Target = SessionPtr;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(&self.0 as *const api::snmp_session as *const SessionPtr) }
    }
}

impl DerefMut for SessionBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(&mut self.0 as *mut api::snmp_session as *mut SessionPtr) }
    }
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionBuilder")
            .field(&(&self.0 as *const api::snmp_session))
            .finish()
    }
}

impl Drop for SessionBuilder {
    fn drop(&mut self) {
        if !self.0.peername.is_null() {
            mem::drop(unsafe { CString::from_raw(self.0.peername) });
        }
        if !self.0.community.is_null() {
            mem::drop(unsafe {
                Box::from_raw(std::slice::from_raw_parts_mut(
                    self.0.community,
                    self.0.community_len,
                ))
            });
        }
        if !self.0.securityName.is_null() {
            mem::drop(unsafe { CString::from_raw(self.0.securityName) });
        }
        /*if !self.0.callback_magic.is_null() {
            mem::drop(unsafe { Box::from_raw(self.0.callback_magic) })
        }*/
    }
}
