# NetSNMP-rs

This crate provides Rust bindings for a subset of NetSNMP
functionality. It supports async queries over SNMPv1, SNMPv2 and
SNMPv3. It depends on a patched netsnmp library to fix thread-safety
and async API problems for SNMPv3.

Note: needs to be updated and tested thoroughly. Do not use for
production in its current state!
