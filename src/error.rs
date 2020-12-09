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

use std::convert::From;
use std::ffi::NulError;
use std::fmt;

use super::oid::Oid;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub enum Error {
    General(String),
    Transport(String, String),
    Packet(String),
    Response(String),
    Usm(String),
    KeyError,
    OidsNotIncreasing,
    OidParseError,
    NoSuchObject(Oid),
    InvalidCallbackOp(i32),
    InvalidMsg(u32),
    InvalidVersion(u32),
    UnsupportedVersion(&'static str),
    NulError(NulError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::General(msg) => write!(f, "{}", msg),
            Error::Transport(app, addr) => write!(f, "Error in transport {} on {}", app, addr),
            Error::Packet(msg) => write!(f, "Error in packet: {}", msg),
            Error::Response(msg) => write!(f, "{}", msg),
            Error::Usm(msg) => write!(f, "Usm error: {}", msg),
            Error::KeyError => write!(f, "Key loading failed"),
            Error::OidsNotIncreasing => write!(f, "Oids not increasing"),
            Error::OidParseError => write!(f, "Failed to parse Oid component"),
            Error::NoSuchObject(oid) => write!(f, "No such object available at Oid {}", oid),
            Error::InvalidCallbackOp(val) => write!(f, "Invalid callback op code: {}", val),
            Error::InvalidMsg(val) => write!(f, "Invalid message code: {}", val),
            Error::InvalidVersion(val) => write!(f, "Invalid version code: {}", val),
            Error::UnsupportedVersion(val) => write!(f, "Unsupported snmp version: {}", val),
            Error::NulError(err) => write!(f, "{}", err),
        }
    }
}

impl std::error::Error for Error {}

impl From<NulError> for Error {
    fn from(err: NulError) -> Error {
        Error::NulError(err)
    }
}
