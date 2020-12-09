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

use std::ops::{Deref, DerefMut};
use std::{mem, slice};

use super::api;
use super::oid::Oid;
use super::types::{ErrType, VarType};
use super::value::Value;

/// Owned variable managed by rust.
pub struct Variable(Box<api::netsnmp_variable_list>);

/// Pointer to a variable managed by netsnmp.
pub struct VariablePtr(api::netsnmp_variable_list);

impl Variable {}

impl VariablePtr {
    pub unsafe fn from_raw<'a>(ptr: *const api::netsnmp_variable_list) -> &'a Self {
        &*(ptr as *const VariablePtr)
    }

    pub fn to_owned(&self) -> Variable {
        unsafe {
            let mut var = Box::new(mem::zeroed());
            api::snmp_clone_var(
                &self.0 as *const api::variable_list as *mut api::variable_list,
                &mut *var,
            );
            Variable(var)
        }
    }

    pub fn print(&self) {
        unsafe {
            api::print_variable(self.0.name, self.0.name_length, &self.0);
        }
    }

    pub fn get_name(&self) -> Oid {
        unsafe { Oid::from_slice(slice::from_raw_parts(self.0.name, self.0.name_length)) }
    }

    pub fn get_type(&self) -> std::result::Result<VarType, ErrType> {
        match self.0.type_ {
            0x01 => Ok(VarType::Boolean),
            0x02 => Ok(VarType::Integer),
            0x03 => Ok(VarType::BitStr),
            0x04 => Ok(VarType::OctetStr),
            0x05 => Ok(VarType::Null),
            0x06 => Ok(VarType::Oid),
            0x40 => Ok(VarType::IpAddress),
            0x41 => Ok(VarType::Counter),
            0x42 => Ok(VarType::Gauge),
            0x43 => Ok(VarType::TimeTicks),
            0x46 => Ok(VarType::Counter64),
            0x48 => Ok(VarType::Float),
            0x49 => Ok(VarType::Double),
            0x50 => Ok(VarType::Integer64),
            0x51 => Ok(VarType::Unsigned64),

            0x00 => Err(ErrType::Undefined),
            0x80 => Err(ErrType::NoSuchObject),
            0x81 => Err(ErrType::NoSuchInstance),
            0x82 => Err(ErrType::EndOfMibView),
            typ => Err(ErrType::NotImplemented(typ)),
        }
    }

    pub fn get_value(&self) -> std::result::Result<Value, ErrType> {
        unsafe {
            match self.get_type()? {
                VarType::Boolean => Ok(Value::Boolean(*self.0.val.integer > 0)),
                VarType::Integer => Ok(Value::Integer(*self.0.val.integer)),
                VarType::Integer32 => Ok(Value::Integer(*self.0.val.integer)),
                VarType::TimeTicks => Ok(Value::TimeTicks(*self.0.val.integer as u64)),
                VarType::Gauge => Ok(Value::Gauge(*self.0.val.integer as u64)),
                VarType::Counter => Ok(Value::Counter(*self.0.val.integer as u64)),
                VarType::Counter64 => Ok(Value::Counter64(
                    ((*self.0.val.counter64).high << 32 | (*self.0.val.counter64).low) as u64,
                )),
                VarType::Integer64 => Ok(Value::Integer64(
                    ((*self.0.val.counter64).high << 32 | (*self.0.val.counter64).low) as i64,
                )),
                VarType::Unsigned64 => Ok(Value::Unsigned64(
                    ((*self.0.val.counter64).high << 32 | (*self.0.val.counter64).low) as u64,
                )),
                VarType::BitStr => {
                    //eprintln!("Bit string with length {}", self.0.val_len);
                    Ok(Value::BitStr(
                        slice::from_raw_parts(self.0.val.bitstring, self.0.val_len).to_vec(),
                    ))
                }
                VarType::OctetStr => Ok(Value::OctetStr(
                    slice::from_raw_parts(self.0.val.string, self.0.val_len).to_vec(),
                )),
                VarType::Oid => Ok(Value::Oid(Oid::from_slice(slice::from_raw_parts(
                    self.0.val.objid,
                    self.0.val_len / mem::size_of::<api::oid>(),
                )))),
                VarType::IpAddress => Ok(Value::IpAddress(*self.0.val.integer as u32)),
                VarType::Null => Ok(Value::Null),

                VarType::MacAddress => panic!(
                    "got unexpected MacAddress type from SNMP (should always map to OCTET STRING)"
                ),

                VarType::Sequence => Err(ErrType::NotImplemented(VarType::Sequence as u8)),
                VarType::Set => Err(ErrType::NotImplemented(VarType::Set as u8)),
                VarType::Opaque => Err(ErrType::NotImplemented(VarType::Opaque as u8)),
                VarType::Float => Err(ErrType::NotImplemented(VarType::Float as u8)),
                VarType::Double => Err(ErrType::NotImplemented(VarType::Double as u8)),
                /* Should never happen when all types from get_type are implemented;
                 * disable panic to trigger warning at compile time.*/
                //typ => panic!("unimplemented variable type {:?}", typ)
            }
        }
    }
}

impl Deref for Variable {
    type Target = VariablePtr;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(&*self.0 as *const api::variable_list as *const VariablePtr) }
    }
}

impl DerefMut for Variable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(&mut *self.0 as *mut api::variable_list as *mut VariablePtr) }
    }
}

impl Drop for Variable {
    fn drop(&mut self) {
        unsafe {
            // Only free internals since the structure itself is allocated by rust.
            api::snmp_free_var_internals(&mut *self.0);
        }
    }
}
