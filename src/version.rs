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

use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use super::api;
use super::error::{Error, Result};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "version")]
#[repr(u32)]
pub enum Version {
    #[serde(rename = "1")]
    V1 = api::SNMP_VERSION_1,
    #[serde(rename = "2c")]
    V2c = api::SNMP_VERSION_2c,
    #[serde(rename = "3")]
    V3 = api::SNMP_VERSION_3,
}

impl TryFrom<u32> for Version {
    type Error = Error;
    fn try_from(val: u32) -> Result<Self> {
        match val {
            api::SNMP_VERSION_1 => Ok(Self::V1),
            api::SNMP_VERSION_2c => Ok(Self::V2c),
            api::SNMP_VERSION_3 => Ok(Self::V3),
            api::SNMP_VERSION_2u => Err(Error::UnsupportedVersion("v2u")),
            api::SNMP_VERSION_2p => Err(Error::UnsupportedVersion("v2p")),
            api::SNMP_VERSION_sec => Err(Error::UnsupportedVersion("v2sec")),
            api::SNMP_VERSION_2star => Err(Error::UnsupportedVersion("v2*")),
            _ => Err(Error::InvalidVersion(val)),
        }
    }
}
