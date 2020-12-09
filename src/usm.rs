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

use std::ffi::CString;
use std::marker::PhantomData;
use std::mem;

use super::api;
use super::auth::{V3AuthParams, V3AuthProtocol, V3Level, V3PrivParams, V3PrivProtocol};
use super::{Error, Result};

pub struct Usm<'a>(PhantomData<&'a ()>);
pub struct UsmUser<'a>(*mut api::usmUser, PhantomData<&'a ()>);

impl<'a> Usm<'a> {
    pub fn init() -> Self {
        unsafe {
            api::init_usm();
        }
        Self(PhantomData)
    }

    pub fn create_user<'b>(&self) -> UsmUser<'b>
    where
        'a: 'b,
    {
        unsafe { UsmUser(api::usm_create_user(), PhantomData) }
    }

    pub fn add_user(&mut self, user: UsmUser) -> Result<()> {
        unsafe {
            match api::usm_add_user(user.0).is_null() {
                true => Err(Error::Usm(String::from("Failed to register user."))),
                false => {
                    mem::forget(user);
                    Ok(())
                }
            }
        }
    }
}

impl<'a> UsmUser<'a> {
    pub fn set_name(self, name: &str) -> Result<Self> {
        unsafe {
            (*self.0).name = CString::new(name)
                .map_err(|_| Error::Usm(String::from("Invalid name")))?
                .into_raw();
            Ok(self)
        }
    }

    pub fn set_sec_name(self, name: &str) -> Result<Self> {
        unsafe {
            (*self.0).secName = CString::new(name)
                .map_err(|_| Error::Usm(String::from("Invalid security name")))?
                .into_raw();
            Ok(self)
        }
    }

    pub fn set_engine_id(self, id: &[u8]) -> Self {
        unsafe {
            let mut id = id.to_vec();
            (*self.0).engineIDLen = id.len();
            (*self.0).engineID = id.as_mut_ptr();
            mem::forget(id); /* Do not free the id now! */
            self
        }
    }

    pub fn set_auth(self, level: &V3Level) -> Result<Self> {
        match &level {
            V3Level::NoAuthNoPriv => Ok(self),
            V3Level::AuthNoPriv { auth } => self.set_v3_auth(auth),
            V3Level::AuthPriv { auth, privacy } => self.set_v3_auth(auth)?.set_v3_priv(privacy),
        }
    }

    fn set_v3_auth(self, params: &V3AuthParams) -> Result<Self> {
        unsafe {
            (*self.0).secName = CString::new(params.user.clone()).unwrap().into_raw();

            let (authproto, authproto_len) = match params.protocol {
                V3AuthProtocol::MD5 => (
                    api::usmHMACMD5AuthProtocol.as_ptr().cast_mut(),
                    api::USM_AUTH_PROTO_MD5_LEN as usize,
                ),
                V3AuthProtocol::SHA => (
                    api::usmHMACSHA1AuthProtocol.as_ptr().cast_mut(),
                    api::USM_AUTH_PROTO_SHA_LEN as usize,
                ),
            };

            (*self.0).authProtocol = authproto;
            (*self.0).authProtocolLen = authproto_len;

            let password = CString::new(params.password.as_str()).unwrap().into_bytes();

            let mut ku: Vec<u8> = Vec::with_capacity(32);
            let mut ku_len: usize = ku.capacity();

            let mut authkey: Vec<u8> = Vec::with_capacity(32);
            (*self.0).authKey = authkey.as_mut_ptr();
            (*self.0).authKeyLen = authkey.capacity();

            if api::generate_Ku(
                (*self.0).authProtocol,
                (*self.0).authProtocolLen as u32,
                &password[0],
                password.len(),
                ku.as_mut_ptr(),
                &mut ku_len,
            ) != (api::SNMPERR_SUCCESS as i32)
            {
                return Err(Error::KeyError);
            }

            if api::generate_kul(
                (*self.0).authProtocol,
                (*self.0).authProtocolLen as u32,
                (*self.0).engineID,
                (*self.0).engineIDLen,
                ku.as_mut_ptr(),
                ku_len,
                (*self.0).authKey,
                &mut (*self.0).authKeyLen,
            ) != (api::SNMPERR_SUCCESS as i32)
            {
                return Err(Error::KeyError);
            }

            Ok(self)
        }
    }

    fn set_v3_priv(self, params: &V3PrivParams) -> Result<Self> {
        unsafe {
            let (privproto, privproto_len) = match params.protocol {
                V3PrivProtocol::DES => (
                    api::usmDESPrivProtocol.as_ptr().cast_mut(),
                    api::USM_PRIV_PROTO_DES_LEN as usize,
                ),
                V3PrivProtocol::AES => (
                    api::usmAESPrivProtocol.as_ptr().cast_mut(),
                    api::USM_PRIV_PROTO_AES_LEN as usize,
                ),
            };

            (*self.0).privProtocol = privproto;
            (*self.0).privProtocolLen = privproto_len;

            let mut password = CString::new(params.password.as_str()).unwrap().into_bytes();

            let mut ku: Vec<u8> = Vec::with_capacity(32);
            let mut ku_len: usize = ku.capacity();

            let mut privkey: Vec<u8> = Vec::with_capacity(32);
            (*self.0).privKey = privkey.as_mut_ptr();
            (*self.0).privKeyLen = privkey.capacity();
            mem::forget(privkey);

            if api::generate_Ku(
                (*self.0).authProtocol,
                (*self.0).authProtocolLen as u32,
                &mut password[0],
                password.len(),
                ku.as_mut_ptr(),
                &mut ku_len,
            ) != (api::SNMPERR_SUCCESS as i32)
            {
                return Err(Error::KeyError);
            }

            if api::generate_kul(
                (*self.0).authProtocol,
                (*self.0).authProtocolLen as u32,
                (*self.0).engineID,
                (*self.0).engineIDLen,
                ku.as_mut_ptr(),
                ku_len,
                (*self.0).privKey,
                &mut (*self.0).privKeyLen,
            ) != (api::SNMPERR_SUCCESS as i32)
            {
                return Err(Error::KeyError);
            }

            Ok(self)
        }
    }
}

impl<'a> Drop for Usm<'a> {
    fn drop(&mut self) {
        // Not supported in centos 6!
        // unsafe { api::shutdown_usm() }
    }
}

impl<'a> Drop for UsmUser<'a> {
    fn drop(&mut self) {
        unsafe {
            api::usm_free_user(self.0);
        }
    }
}
