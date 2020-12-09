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
use std::mem;
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_char, c_void};

use super::api;
use super::error::{Error, Result};
use super::netsnmp::NetSNMP;

#[derive(Debug)]
pub struct Transport(*mut api::netsnmp_transport);

#[derive(Debug)]
pub struct TransportPtr(api::netsnmp_transport);

// This is most likely not true!
unsafe impl Send for Transport {}
unsafe impl Send for TransportPtr {}

impl Transport {
    pub fn server(_snmp: &NetSNMP, app: &str, addr: &str) -> Result<Self> {
        unsafe {
            let c_app = CString::new(app)?;
            let c_addr = CString::new(addr)?;
            match api::netsnmp_transport_open_server(c_app.into_raw(), c_addr.into_raw()) {
                ptr if ptr.is_null() => Err(Error::Transport(app.to_string(), addr.to_string())),
                ptr => Ok(Transport(ptr)),
            }
        }
    }

    pub fn client(_snmp: &NetSNMP, app: &str, addr: &str) -> Result<Self> {
        unsafe {
            let c_app = CString::new(app)?;
            let c_addr = CString::new(addr)?;
            match api::netsnmp_transport_open_client(
                c_app.as_ptr() as *mut c_char,
                c_addr.as_ptr() as *mut c_char,
            ) {
                ptr if ptr.is_null() => Err(Error::Transport(app.to_string(), addr.to_string())),
                ptr => Ok(Transport(ptr)),
            }
        }
    }

    pub fn into_raw(self) -> *mut api::netsnmp_transport {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }
}

impl TransportPtr {
    pub unsafe fn from_ptr<'a>(ptr: *mut api::netsnmp_transport) -> &'a mut Self {
        &mut *(ptr as *mut TransportPtr)
    }

    pub fn as_transport_ptr(&self) -> &Self {
        self
    }

    pub fn as_ptr(&self) -> *const api::netsnmp_transport {
        &self.0
    }

    pub fn as_mut_ptr(&mut self) -> *mut api::netsnmp_transport {
        &mut self.0
    }

    pub fn socket_fd(&self) -> i32 {
        self.0.sock
    }

    pub fn socket_fd_ref(&self) -> &i32 {
        &self.0.sock
    }

    pub fn format_nolookup(&mut self, data: &mut [u8]) -> Option<String> {
        let flags = self.0.flags;
        self.0.flags &= !api::NETSNMP_TRANSPORT_FLAG_HOSTNAME;
        let res = self.format(data);
        self.0.flags = flags;
        res
    }

    pub fn format_lookup(&mut self, data: &mut [u8]) -> Option<String> {
        let flags = self.0.flags;
        self.0.flags |= api::NETSNMP_TRANSPORT_FLAG_HOSTNAME;
        let res = self.format(data);
        self.0.flags = flags;
        res
    }

    pub fn format(&mut self, data: &mut [u8]) -> Option<String> {
        match self.0.f_fmtaddr {
            Some(fmtaddr) => {
                let res = unsafe {
                    fmtaddr(
                        &mut self.0,
                        data.as_mut_ptr() as *mut c_void,
                        data.len() as i32,
                    )
                };
                match res {
                    ptr if ptr.is_null() => None,
                    ptr => {
                        let ip = unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() };
                        // Free original data using extern c free?
                        Some(ip)
                    }
                }
            }
            None => None,
        }
    }
}

impl<'a> Deref for Transport {
    type Target = TransportPtr;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.0 as *const TransportPtr) }
    }
}

impl<'a> DerefMut for Transport {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.0 as *mut TransportPtr) }
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        assert!(!self.0.is_null(), "null transport!");
        unsafe {
            api::netsnmp_transport_free(self.0);
        }
    }
}
