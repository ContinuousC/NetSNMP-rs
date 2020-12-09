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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "version")]
pub enum Auth {
    #[serde(rename = "2c")]
    #[serde(alias = "1")]
    V2c(V2cAuth),
    #[serde(rename = "3")]
    V3(V3Auth),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct V2cAuth {
    pub community: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct V3Auth {
    #[serde(flatten)]
    pub level: V3Level,
    // Unimplemented:
    pub context: Option<String>,
    pub context_engine: Option<String>,
    pub security_engine: Option<String>,
    pub destination_engine: Option<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "level")]
pub enum V3Level {
    #[serde(rename = "noAuthNoPriv")]
    NoAuthNoPriv,
    #[serde(rename = "authNoPriv")]
    AuthNoPriv { auth: V3AuthParams },
    #[serde(rename = "authPriv")]
    AuthPriv {
        auth: V3AuthParams,
        #[serde(rename = "priv")]
        privacy: V3PrivParams,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct V3AuthParams {
    pub protocol: V3AuthProtocol,
    pub user: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct V3PrivParams {
    pub protocol: V3PrivProtocol,
    pub password: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum V3AuthProtocol {
    #[serde(alias = "sha")]
    SHA,
    #[serde(alias = "md5")]
    MD5,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum V3PrivProtocol {
    DES,
    AES,
}
