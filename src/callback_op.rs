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

use super::api;
use super::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum CallbackOp {
    ReceivedMessage = api::NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
    TimedOut = api::NETSNMP_CALLBACK_OP_TIMED_OUT,
    SendFailed = api::NETSNMP_CALLBACK_OP_SEND_FAILED,
    Connect = api::NETSNMP_CALLBACK_OP_CONNECT,
    Disconnect = api::NETSNMP_CALLBACK_OP_DISCONNECT,
    //Resend          = api::NETSNMP_CALLBACK_OP_RESEND,
    //SecError        = api::NETSNMP_CALLBACK_OP_SEC_ERROR,
}

impl TryFrom<i32> for CallbackOp {
    type Error = Error;
    fn try_from(val: i32) -> Result<Self> {
        match val as u32 {
            api::NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE => Ok(Self::ReceivedMessage),
            api::NETSNMP_CALLBACK_OP_TIMED_OUT => Ok(Self::TimedOut),
            api::NETSNMP_CALLBACK_OP_SEND_FAILED => Ok(Self::SendFailed),
            api::NETSNMP_CALLBACK_OP_CONNECT => Ok(Self::Connect),
            api::NETSNMP_CALLBACK_OP_DISCONNECT => Ok(Self::Disconnect),
            //api::NETSNMP_CALLBACK_OP_RESEND => Ok(Self::Resend),
            //api::NETSNMP_CALLBACK_OP_SEC_ERROR => Ok(Self::SecError),
            _ => Err(Error::InvalidCallbackOp(val)),
        }
    }
}
