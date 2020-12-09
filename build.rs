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

#[cfg(feature = "bindgen")]
extern crate bindgen;

#[cfg(feature = "bindgen")]
use std::env;
#[cfg(feature = "bindgen")]
use std::path::PathBuf;

#[cfg(feature = "bindgen")]
fn main() {
    let lib_paths = &[
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/lib64"),
        PathBuf::from("/usr/lib/x86_64-linux-gnu"),
        PathBuf::from("/usr/local/lib"),
    ];

    // Use our modified netsnmp library for async support. */
    let (netsnmp_lib_name, include_path) =
        match env::var("CARGO_FEATURE_TOKIO").is_ok_and(|v| !v.is_empty()) {
            true => ("netsnmp_si", "/usr/local/include"),
            false => ("netsnmp", "/usr/include"),
        };

    println!("cargo:rustc-link-lib={}", netsnmp_lib_name);

    let abis = [40, 35, 31];
    let abi = *abis
        .iter()
        .find(|n| {
            lib_paths.iter().any(|path| {
                path.join(format!("lib{}.so.{}", netsnmp_lib_name, n))
                    .exists()
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "No supported netsnmp library found (supported abis: {})\n\
		 Searched for 'lib{}.so.<abi>' in:\n\
		 {}",
                abis.iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                netsnmp_lib_name,
                lib_paths
                    .iter()
                    .map(|p| format!("- {}\n", p.display()))
                    .collect::<Vec<_>>()
                    .concat()
            )
        });

    println!("cargo:rustc-cfg=netsnmp_abi=\"{}\"", abi);

    let generator = bindgen::Builder::default()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .opaque_type("timex") /* Problematic for now, because it contains
        a slice longer than 32. Remove when generic trait derivation lands. */
        .header(format!("{}/net-snmp/net-snmp-config.h", include_path))
        .header(format!("{}/net-snmp/net-snmp-includes.h", include_path))
        .header(format!("{}/net-snmp/library/large_fd_set.h", include_path));

    //println!("cargo:rerun-if-changed=netsnmp.h");
    //generator = generator.header("netsnmp.h")

    let bindings = generator.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(not(feature = "bindgen"))]
fn main() {}
