//! # Rusticata-macros
//!
//! Helper macros for the [rusticata](https://github.com/rusticata) project.

#![deny(missing_docs,unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]

#[macro_use]
extern crate nom;

pub use macros::*;
#[macro_use]
pub mod macros;

pub mod debug;
