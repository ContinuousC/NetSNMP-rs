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

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum VarType {
    /* asn1.h */
    Boolean = 0x01, /* ASN_BOOLEAN */
    #[serde(alias = "INTEGER")]
    Integer = 0x02, /* ASN_INTEGER */
    Integer32 = 0xfe, /* Same as INTEGER for netsnmp (?),
                    different in MIB Syntax (eg. no enums) */
    #[serde(alias = "BITSTRING")]
    BitStr = 0x03, /* ASN_BIT_STR */
    #[serde(alias = "OCTET STRING")]
    OctetStr = 0x04, /* ASN_OCTET_STR */
    Null = 0x05, /* ASN_NULL */
    #[serde(alias = "OBJECT-IDENTITY")]
    #[serde(alias = "OID")]
    Oid = 0x06, /* ASN_OBJECT_ID */
    Sequence = 0x10, /* ASN_SEQUENCE */
    Set = 0x11,  /* ASN_SET */

    /* snmp_impl.h */
    #[serde(alias = "IpAddress")]
    IpAddress = 0x40,
    #[serde(alias = "Counter32")]
    Counter = 0x41,
    #[serde(alias = "Unsigned32")]
    #[serde(alias = "Gauge32")]
    Gauge = 0x42,
    #[serde(alias = "Timeticks")]
    TimeTicks = 0x43,
    Opaque = 0x44, /* changed so no conflict with other includes */
    Counter64 = 0x46,

    Float = 0x48,
    Double = 0x49,
    Integer64 = 0x50,
    Unsigned64 = 0x51,

    /* Not defined in SNMP! */
    #[serde(alias = "MacAddress")]
    MacAddress = 0xff,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum ErrType {
    Undefined,          /* 0x00, seen with "empty" oids */
    NotImplemented(u8), /* not defined by netsnmp; used when we do not known the type */

    /* snmp.h */
    NoSuchObject,   /* 0x80*/
    NoSuchInstance, /* 0x81 */
    EndOfMibView,   /* 0x82 */
}
