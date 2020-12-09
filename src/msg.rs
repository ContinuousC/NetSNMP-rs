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

use super::api;
use super::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum Msg {
    Get = api::SNMP_MSG_GET,
    GetNext = api::SNMP_MSG_GETNEXT,
    Response = api::SNMP_MSG_RESPONSE,
    Set = api::SNMP_MSG_SET,
    GetBulk = api::SNMP_MSG_GETBULK,
    Inform = api::SNMP_MSG_INFORM,
    Trap = api::SNMP_MSG_TRAP,
    Trap2 = api::SNMP_MSG_TRAP2,
    Report = api::SNMP_MSG_REPORT,
}

impl TryFrom<u32> for Msg {
    type Error = Error;
    fn try_from(val: u32) -> Result<Self> {
        match val {
            api::SNMP_MSG_GET => Ok(Self::Get),
            api::SNMP_MSG_GETNEXT => Ok(Self::GetNext),
            api::SNMP_MSG_RESPONSE => Ok(Self::Response),
            api::SNMP_MSG_SET => Ok(Self::Set),
            api::SNMP_MSG_GETBULK => Ok(Self::GetBulk),
            api::SNMP_MSG_INFORM => Ok(Self::Inform),
            api::SNMP_MSG_TRAP => Ok(Self::Trap),
            api::SNMP_MSG_TRAP2 => Ok(Self::Trap2),
            api::SNMP_MSG_REPORT => Ok(Self::Report),
            _ => Err(Error::InvalidMsg(val)),
        }
    }
}
