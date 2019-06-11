
// add missing_docs
#![deny(unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]

#[macro_use]
extern crate nom;

pub use ntp::*;
pub mod ntp;
