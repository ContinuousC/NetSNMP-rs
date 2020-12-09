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

use std::ffi::CStr;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_char;
use std::{fmt, mem};

use super::api;
use super::error::{Error, Result};
use super::pdu::Pdu;
use super::session::{SessionInfo, SessionPtr, SyncQuery};

/// An owned, heap allocated open session opened via the original multi-session API (not thread safe).
pub struct MultiSession(*mut api::snmp_session);

/// A smart pointer to a session opened via the original multi-session API (not thread safe).
pub struct MultiSessionPtr(api::snmp_session);

impl MultiSession {
    pub unsafe fn from_raw(ptr: *mut api::snmp_session) -> Self {
        Self(ptr)
    }

    pub fn into_raw(self) -> *mut api::snmp_session {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }
}

impl MultiSessionPtr {
    pub unsafe fn from_ptr<'a>(ptr: *const api::snmp_session) -> &'a Self {
        &*(ptr as *const Self)
    }

    pub unsafe fn from_mut<'a>(ptr: *mut api::snmp_session) -> &'a mut Self {
        &mut *(ptr as *mut Self)
    }

    pub fn as_raw(&self) -> *const api::snmp_session {
        &self.0 as *const api::snmp_session
    }
}

impl SyncQuery for MultiSessionPtr {
    fn synch_response(&mut self, pdu: Pdu) -> Result<Pdu> {
        unsafe {
            let mut response = mem::zeroed();
            let status = api::snmp_synch_response(&mut self.0, pdu.as_raw(), &mut response);

            if status == (api::STAT_SUCCESS as i32) {
                mem::forget(pdu);
                if (*response).errstat == (api::SNMP_ERR_NOERROR as i64) {
                    Ok(Pdu::from_raw(response))
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
            if api::snmp_send(&mut self.0, pdu.as_raw()) != 0 {
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

impl Deref for MultiSession {
    type Target = MultiSessionPtr;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.0 as *const MultiSessionPtr) }
    }
}

impl DerefMut for MultiSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.0 as *mut MultiSessionPtr) }
    }
}

impl SessionInfo for MultiSessionPtr {
    fn session(&self) -> &SessionPtr {
        unsafe { &*(self as *const MultiSessionPtr as *const SessionPtr) }
    }
    fn session_mut(&mut self) -> &mut SessionPtr {
        unsafe { &mut *(self as *mut MultiSessionPtr as *mut SessionPtr) }
    }
}

impl fmt::Debug for MultiSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MutliSession").field(&self.0).finish()
    }
}

impl fmt::Debug for MultiSessionPtr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MultiSessionPtr")
            .field(&(&self.0 as *const api::snmp_session))
            .finish()
    }
}

impl Drop for MultiSession {
    fn drop(&mut self) {
        unsafe {
            if !self.session().0.callback_magic.is_null() {
                //mem::drop(Box::from_raw((*self.0).callback_magic));
            }
            api::snmp_close(self.0);
        }
    }
}
