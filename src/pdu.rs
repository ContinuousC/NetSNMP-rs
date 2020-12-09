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
use std::ops::{Deref, DerefMut};
use std::{mem, slice};

use super::api;
use super::error::{Error, Result};
use super::msg::Msg;
use super::oid::Oid;
use super::varlist::{VarListIter, VarListPtr};
use super::version::Version;

/// An owned pdu managed by netsnmp.
#[derive(Debug)]
pub struct Pdu(*mut api::snmp_pdu);

/// A smart pointer to a pdu managed by netsnmp.
#[derive(Debug)]
pub struct PduPtr(api::snmp_pdu);

unsafe impl Send for Pdu {}
unsafe impl Send for PduPtr {}

impl Pdu {
    pub unsafe fn from_raw(ptr: *mut api::snmp_pdu) -> Self {
        Self(ptr)
    }

    pub fn as_raw(&self) -> *mut api::snmp_pdu {
        self.0
    }

    pub fn into_raw(self) -> *mut api::snmp_pdu {
        let ptr = self.0;
        mem::forget(self);
        ptr
    }

    fn new(msg: Msg) -> Self {
        unsafe { Self(api::snmp_pdu_create(msg as i32)) }
    }

    pub fn get() -> Self {
        Self::new(Msg::Get)
    }

    pub fn get_next() -> Self {
        Self::new(Msg::GetNext)
    }

    pub fn get_bulk(non_repeaters: i64, max_repetitions: i64) -> Self {
        let pdu = Self::new(Msg::GetBulk);
        unsafe {
            (*pdu.0).errstat = non_repeaters; /* see non_repeaters define */
            (*pdu.0).errindex = max_repetitions; /* see max_repetitions define */
            pdu
        }
    }

    pub fn add_oid(self, oid: &Oid) -> Self {
        unsafe {
            api::snmp_add_null_var(self.0, oid.as_ptr(), oid.len());
            self
        }
    }
}

impl PduPtr {
    pub unsafe fn from_ptr<'a>(ptr: *mut api::snmp_pdu) -> &'a Self {
        &*(ptr as *mut Self)
    }

    pub fn as_ptr(&self) -> *const api::snmp_pdu {
        &self.0 as *const api::snmp_pdu
    }

    pub fn as_mut(&mut self) -> *mut api::snmp_pdu {
        &mut self.0 as *mut api::snmp_pdu
    }

    pub fn to_owned(&self) -> Pdu {
        unsafe {
            let ptr = api::snmp_clone_pdu(&self.0 as *const api::snmp_pdu as *mut api::snmp_pdu);
            assert!(!ptr.is_null(), "snmp_clone_pdu failed!");
            Pdu::from_raw(ptr)
        }
    }

    pub fn command(&self) -> Result<Msg> {
        Msg::try_from(self.0.command as u32)
    }

    pub fn set_command(&mut self, msg: Msg) {
        self.0.command = msg as i32;
    }

    pub fn clear_error(&mut self) {
        self.0.errstat = 0;
        self.0.errindex = 0;
    }

    pub fn agent_addr(&self) -> [u8; 4] {
        self.0.agent_addr
    }

    pub fn version(&self) -> Result<Version> {
        Version::try_from(self.0.version as u32)
    }

    pub fn flags(&self) -> u64 {
        self.0.flags
    }

    pub fn community(&self) -> Result<String> {
        let text = unsafe { slice::from_raw_parts(self.0.community, self.0.community_len) };
        String::from_utf8(text.to_vec())
            .map_err(|_| Error::General(format!("Community string is not valid utf8!")))
    }

    pub fn enterprise(&self) -> Oid {
        unsafe {
            Oid::from_slice(slice::from_raw_parts(
                self.0.enterprise,
                self.0.enterprise_length,
            ))
        }
    }

    pub fn trap_type(&self) -> u64 {
        self.0.trap_type as u64
    }

    pub fn specific_type(&self) -> u64 {
        self.0.specific_type as u64
    }

    pub fn variables<'a>(&'a self) -> VarListIter<'a> {
        unsafe { VarListPtr::from_ptr(self.0.variables).into_iter() }
    }

    pub fn transport_data(&self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(
                self.0.transport_data as *mut u8,
                self.0.transport_data_length as usize,
            )
        }
    }
}

impl Deref for Pdu {
    type Target = PduPtr;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.0 as *const PduPtr) }
    }
}

impl DerefMut for Pdu {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.0 as *mut PduPtr) }
    }
}

impl Drop for Pdu {
    fn drop(&mut self) {
        unsafe {
            api::snmp_free_pdu(self.0);
        }
    }
}
