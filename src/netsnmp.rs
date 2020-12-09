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
use std::mem;

use super::api;
use super::error::Result;
use super::session_builder::SessionBuilder;
use super::transport::Transport;

#[derive(Debug)]
pub struct NetSNMP {
    _app: CString,
}

pub fn init(app: &str) -> NetSNMP {
    NetSNMP::init(app)
}

/// Object to manage library-wide functions.
impl NetSNMP {
    /// Initialize library.
    pub fn init(app: &str) -> NetSNMP {
        let app = CString::new(app).unwrap();
        unsafe {
            api::init_snmp(app.as_ptr());
        }
        NetSNMP { _app: app }
    }

    pub fn session(&self) -> SessionBuilder {
        SessionBuilder::new(self)
    }

    pub fn server_transport(&self, app: &str, addr: &str) -> Result<Transport> {
        Transport::server(self, app, addr)
    }

    pub fn client_transport(&self, app: &str, addr: &str) -> Result<Transport> {
        Transport::client(self, app, addr)
    }

    pub fn read(&self) {
        unsafe {
            let mut numfds = 0;
            let mut block = 1;
            let mut timeout: api::timeval = mem::zeroed();
            let mut readfds = mem::zeroed();
            //timeout.tv_sec = 5;
            api::snmp_select_info(&mut numfds, &mut readfds, &mut timeout, &mut block);
            //println!("Snmp_read r = {:?}", r);
            api::snmp_read(&mut readfds);
        }
    }

    pub fn read_or_wake(&self, fd: i32) {
        unsafe {
            let mut nfds = 0;
            let mut block = 0;
            let mut timeout: api::timeval = mem::zeroed();
            let mut readfds: api::fd_set = mem::zeroed();
            api::snmp_select_info(&mut nfds, &mut readfds, &mut timeout, &mut block);
            readfds.__fds_bits[(fd >> 6) as usize] |= 1 << fd;
            nfds = (nfds - 1).max(fd) + 1;
            api::select(
                nfds,
                &mut readfds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                if block > 0 {
                    std::ptr::null_mut()
                } else {
                    &mut timeout
                },
            );
            api::snmp_read(&mut readfds);
        }
    }

    pub fn set_debug(&self, enable: bool) {
        unsafe {
            api::snmp_set_do_debugging(match enable {
                true => 1,
                false => 0,
            });
        }
    }
}
