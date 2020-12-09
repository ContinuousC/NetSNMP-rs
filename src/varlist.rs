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

use super::api;
use super::variable::VariablePtr;

/// Owned variable list managed by netsnmp.
#[derive(Debug)]
pub struct VarList(*mut api::netsnmp_variable_list);

/// Smart pointer to a variable list managed by netsnmp.
pub struct VarListPtr(api::netsnmp_variable_list);

/// Iterator over a varlist.
pub struct VarListIter<'a> {
    _varlist: &'a VarListPtr,
    next: *const api::netsnmp_variable_list,
}

impl VarList {
    pub unsafe fn from_raw(ptr: *mut api::netsnmp_variable_list) -> Self {
        VarList(ptr)
    }

    pub fn as_raw(&self) -> *mut api::netsnmp_variable_list {
        self.0
    }

    pub fn into_raw(self) -> *mut api::netsnmp_variable_list {
        let ptr = self.as_raw();
        std::mem::forget(self);
        ptr
    }
}

impl VarListPtr {
    pub unsafe fn from_ptr<'a>(ptr: *const api::netsnmp_variable_list) -> &'a Self {
        &*(ptr as *const VarListPtr)
    }
}

impl<'a> IntoIterator for &'a VarListPtr {
    type IntoIter = VarListIter<'a>;
    type Item = &'a VariablePtr;

    fn into_iter(self) -> Self::IntoIter {
        VarListIter {
            _varlist: self,
            next: &self.0,
        }
    }
}

impl<'a> Iterator for VarListIter<'a> {
    type Item = &'a VariablePtr;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            match self.next.as_ref() {
                None => None, // for VarList, the pointer can be null
                Some(current) => {
                    // for Variable, the pointer is never null!
                    self.next = current.next_variable;
                    Some(VariablePtr::from_raw(current))
                }
            }
        }
    }
}

impl Deref for VarList {
    type Target = VarListPtr;
    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.0 as *const VarListPtr) }
    }
}

impl DerefMut for VarList {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.0 as *mut VarListPtr) }
    }
}

impl Drop for VarList {
    fn drop(&mut self) {
        unsafe {
            api::snmp_free_varbind(self.0);
        }
    }
}
