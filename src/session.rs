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

use super::api;
use super::error::{Error, Result};
use super::oid::Oid;
use super::pdu::Pdu;
use super::variable::{Variable, VariablePtr};

/// A smart pointer to a session (functionality shared between multi and single session API).
/// Only usable for read-only (session information) operations.
pub struct SessionPtr(pub(crate) api::snmp_session);

/// Session information (shared between single and multi API).
pub trait SessionInfo {
    fn session(&self) -> &SessionPtr;
    fn session_mut(&mut self) -> &mut SessionPtr;

    fn is_authoritative(&self) -> bool {
        self.session().is_authoritative()
    }

    fn peername(&self) -> Option<String> {
        self.session().peername()
    }

    fn localname(&self) -> Option<String> {
        self.session().localname()
    }

    fn has_error(&self) -> bool {
        self.session().has_error()
    }
}

impl SessionPtr {
    pub fn is_authoritative(&self) -> bool {
        self.0.isAuthoritative > 0
    }

    pub fn peername(&self) -> Option<String> {
        unsafe {
            match self.0.peername.as_ref() {
                Some(ptr) => Some(CStr::from_ptr(ptr).to_string_lossy().into_owned()),
                None => None,
            }
        }
    }

    pub fn localname(&self) -> Option<String> {
        unsafe {
            match self.0.localname.as_ref() {
                Some(ptr) => Some(CStr::from_ptr(ptr).to_string_lossy().into_owned()),
                None => None,
            }
        }
    }

    pub fn has_error(&self) -> bool {
        self.0.s_errno != 0 || self.0.s_snmp_errno != 0
    }
}

pub trait SyncQuery {
    fn synch_response(&mut self, pdu: Pdu) -> Result<Pdu>;
    fn send(&mut self, pdu: Pdu) -> Result<()>;
    fn get_error(&mut self) -> Error;

    fn get(&mut self, oid: &Oid) -> Result<Option<Variable>> {
        let pdu = Pdu::get().add_oid(oid);
        Ok(self
            .synch_response(pdu)?
            .variables()
            .next()
            .map(VariablePtr::to_owned))
    }

    fn get_next(&mut self, oid: &Oid) -> Result<Option<Variable>> {
        let pdu = Pdu::get_next().add_oid(oid.into());
        Ok(self
            .synch_response(pdu)?
            .variables()
            .into_iter()
            .next()
            .map(|var| var.to_owned()))
    }

    fn get_bulk(&mut self, gets: &[Oid], walks: &[Oid], repetitions: usize) -> Result<Pdu> {
        let mut pdu = Pdu::get_bulk(gets.len() as i64, repetitions as i64);
        for oid in gets {
            pdu = pdu.add_oid(oid);
        }
        for oid in walks {
            pdu = pdu.add_oid(oid);
        }
        self.synch_response(pdu)
    }

    fn get_many(&mut self, oids: &[Oid]) -> Result<Pdu> {
        let mut pdu = Pdu::get_bulk(oids.len() as i64, 1);
        for oid in oids {
            pdu = pdu.add_oid(oid);
        }
        self.synch_response(pdu)
    }
}
