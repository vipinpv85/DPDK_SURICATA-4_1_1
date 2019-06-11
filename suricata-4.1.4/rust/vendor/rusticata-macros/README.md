# rusticata-macros

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/rusticata-macros.svg?branch=master)](https://travis-ci.org/rusticata/rusticata-macros)
[![Crates.io Version](https://img.shields.io/crates/v/rusticata-macros.svg)](https://crates.io/crates/rusticata-macros)

## Overview

Helper macros for Rusticata

This crate contains some additions to [nom](https://github.com/Geal/nom).

For example, the `error_if!` macro allows to test a condition and return an error from the parser if the condition
fails:

```rust
let r = do_parse!(
	s,
	l: be_u8 >>
	error_if!(l < 0, ErrorKind::Custom(128)) >>
	data: take!(l - 4) >>
	);
```

See the documentation for more details and examples.

## Documentation

Crate is documented, do running `cargo doc` will crate the offline documentation.

Reference documentation can be found [here](https://docs.rs/rusticata-macros/)

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

