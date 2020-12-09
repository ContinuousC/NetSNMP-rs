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

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(improper_ctypes)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/* Defines missed by bindgen */

/*
pub const SNMP_MSG_GET : i32 = 160;
pub const SNMP_MSG_GETNEXT : i32 = 161;
pub const SNMP_MSG_RESPONSE : i32 = 162;
pub const SNMP_MSG_SET : i32 = 163;
pub const SNMP_MSG_GETBULK : i32 = 165;

pub const SNMP_MSG_TRAP : i32 = 164;
pub const SNMP_MSG_INFORM : i32 = 166;
pub const SNMP_MSG_TRAP2 : i32 = 167;
pub const SNMP_MSG_REPORT : i32 = 168;
*/

extern "C" {
    pub fn snmpv3_engineID_probe(arg1: *mut session_list, arg2: *mut snmp_session);
}
