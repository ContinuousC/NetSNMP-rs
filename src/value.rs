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

use super::oid::Oid;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Value {
    Boolean(bool),
    Integer(i64),
    BitStr(Vec<u8>),
    OctetStr(Vec<u8>),
    Null,
    #[serde(alias = "OID")]
    Oid(Oid),
    Sequence,
    Set,
    IpAddress(u32),
    MacAddress(u64),
    Counter(u64),
    Gauge(u64),
    TimeTicks(u64),
    Opaque,
    Counter64(u64),
    Float(f32),
    Double(f64),
    Integer64(i64),
    Unsigned64(u64),
}
