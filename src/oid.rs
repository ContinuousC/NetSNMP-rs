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
use std::ffi::CString;
use std::str::FromStr;
use std::{fmt, slice};

use super::api;
use super::error::{Error, Result};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct Oid(Vec<u64>);

impl Oid {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn from_slice(slice: &[u64]) -> Self {
        Self(slice.to_vec())
    }

    pub fn as_ptr(&self) -> *const u64 {
        self.0.as_ptr()
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn in_table(&self, table: &Oid) -> Oid {
        Oid(self.0.iter().skip(table.0.len()).map(|e| *e).collect())
    }

    pub fn join<T: IntoIterator<Item = u64>>(&self, oid: T) -> Oid {
        let mut new = self.clone();
        new.0.extend(oid);
        new
    }

    pub fn from_symbol<T: AsRef<str>>(sym: T) -> Self {
        unsafe {
            let mut oid = [0; api::MAX_OID_LEN as usize];
            let mut len = api::MAX_OID_LEN as usize;
            let symb = CString::new(sym.as_ref()).unwrap();
            api::read_objid(symb.as_ptr(), oid.as_mut_ptr(), &mut len);
            Self(slice::from_raw_parts(oid.as_ptr(), len).to_vec())
        }
    }

    pub fn contains(&self, oid: &Oid) -> bool {
        oid.0.len() >= self.0.len() && &oid.0[..self.0.len()] == &self.0[..]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Extend<u64> for Oid {
    fn extend<T: IntoIterator<Item = u64>>(&mut self, iter: T) {
        self.0.extend(iter);
    }
}

impl FromStr for Oid {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Ok(Oid(value
            .split('.')
            .skip_while(|e| e.is_empty())
            .map(|i| i.parse().map_err(|_e| Error::OidParseError))
            .collect::<Result<Vec<u64>>>()?))
    }
}

impl TryFrom<String> for Oid {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl Into<String> for Oid {
    fn into(self) -> String {
        self.0
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<String>>()
            .join(".")
    }
}

impl Into<Oid> for &Oid {
    fn into(self) -> Oid {
        self.clone()
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<String>>()
                .join(".")
        )
    }
}
